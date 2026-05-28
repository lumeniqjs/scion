// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hub

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"strings"

	"github.com/GoogleCloudPlatform/scion/pkg/api"
	"github.com/GoogleCloudPlatform/scion/pkg/store"
)

// seedGCPIdentityGrants idempotently creates the backing user, dedicated group,
// project-scoped allow policy, and group binding for each trusted GCP identity
// grant. It is best-effort and fail-closed: a seed error only leaves that
// principal without authorization.
func seedGCPIdentityGrants(ctx context.Context, s store.Store, allowlist map[string]GCPIdentityGrant) int {
	seeded := 0
	for rawEmail, grant := range allowlist {
		email := strings.ToLower(strings.TrimSpace(rawEmail))
		if email == "" || grant.ProjectID == "" || len(grant.Scopes) == 0 {
			slog.Warn("skipping invalid GCP identity grant", "email", rawEmail)
			continue
		}

		uid := GCPIdentityUserID(email)
		if err := seedGCPIdentityUser(ctx, s, uid, email); err != nil {
			slog.Warn("failed to seed GCP identity user", "email", email, "error", err)
			continue
		}

		group, err := seedGCPIdentityGroup(ctx, s, uid, email)
		if err != nil {
			slog.Warn("failed to seed GCP identity group", "email", email, "error", err)
			continue
		}

		if err := seedGCPIdentityPolicies(ctx, s, group.ID, email, grant); err != nil {
			slog.Warn("failed to seed GCP identity policy", "email", email, "error", err)
			continue
		}
		seeded++
	}
	return seeded
}

func seedGCPIdentityUser(ctx context.Context, s store.Store, uid, email string) error {
	_, err := s.GetUser(ctx, uid)
	if err == nil {
		return nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	err = s.CreateUser(ctx, &store.User{
		ID:          uid,
		Email:       email,
		DisplayName: gcpIdentitySubjectPrefix + email,
		// Ent user shadows only permit admin/member/viewer. Keep the runtime
		// identity role as gcpIdentityRole; persist a non-admin backing role.
		Role:        store.UserRoleMember,
		Status:      "active",
	})
	if errors.Is(err, store.ErrAlreadyExists) {
		return nil
	}
	return err
}

func seedGCPIdentityGroup(ctx context.Context, s store.Store, uid, email string) (*store.Group, error) {
	slug := gcpIdentitySubjectPrefix + email
	group, err := s.GetGroupBySlug(ctx, slug)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		group = &store.Group{
			ID:          api.NewUUID(),
			Name:        "GCP Identity " + email,
			Slug:        slug,
			Description: "Dedicated authorization group for " + email,
			GroupType:   store.GroupTypeExplicit,
		}
		if err := s.CreateGroup(ctx, group); err != nil && !errors.Is(err, store.ErrAlreadyExists) {
			return nil, err
		}
		if created, err := s.GetGroupBySlug(ctx, slug); err == nil {
			group = created
		}
	}

	err = s.AddGroupMember(ctx, &store.GroupMember{
		GroupID:    group.ID,
		MemberType: store.GroupMemberTypeUser,
		MemberID:   uid,
		Role:       store.GroupMemberRoleMember,
	})
	if err != nil && !errors.Is(err, store.ErrAlreadyExists) {
		return nil, err
	}
	return group, nil
}

func seedGCPIdentityPolicies(ctx context.Context, s store.Store, groupID, email string, grant GCPIdentityGrant) error {
	byResource := map[string][]string{}
	seen := map[string]bool{}
	for _, scope := range grant.Scopes {
		resourceType, action, ok := splitGCPIdentityScope(scope)
		if !ok {
			slog.Warn("skipping invalid GCP identity scope", "email", email, "scope", scope)
			continue
		}
		key := resourceType + ":" + action
		if seen[key] {
			continue
		}
		seen[key] = true
		byResource[resourceType] = append(byResource[resourceType], action)
	}
	if len(byResource) == 0 {
		return nil
	}

	for resourceType, actions := range byResource {
		sort.Strings(actions)
		name := gcpIdentitySubjectPrefix + email + ":" + resourceType
		policy := &store.Policy{
			ID:           api.NewUUID(),
			Name:         name,
			Description:  "Allow " + email + " GCP identity scoped " + resourceType + " actions",
			ScopeType:    store.PolicyScopeProject,
			ScopeID:      grant.ProjectID,
			ResourceType: resourceType,
			Actions:      actions,
			Effect:       store.PolicyEffectAllow,
		}
		if err := ensureGCPIdentityPolicy(ctx, s, policy); err != nil {
			return err
		}
		if err := s.AddPolicyBinding(ctx, &store.PolicyBinding{
			PolicyID:      policy.ID,
			PrincipalType: store.PolicyPrincipalTypeGroup,
			PrincipalID:   groupID,
		}); err != nil && !errors.Is(err, store.ErrAlreadyExists) {
			return err
		}
	}
	return nil
}

func ensureGCPIdentityPolicy(ctx context.Context, s store.Store, policy *store.Policy) error {
	existing, err := s.ListPolicies(ctx, store.PolicyFilter{Name: policy.Name}, store.ListOptions{Limit: 1})
	if err != nil {
		return err
	}
	if existing.TotalCount == 0 {
		return s.CreatePolicy(ctx, policy)
	}

	current := existing.Items[0]
	policy.ID = current.ID
	if current.ScopeType != policy.ScopeType || current.ScopeID != policy.ScopeID || current.ResourceType != policy.ResourceType || current.Effect != policy.Effect || !sameStringSet(current.Actions, policy.Actions) {
		current.ScopeType = policy.ScopeType
		current.ScopeID = policy.ScopeID
		current.ResourceType = policy.ResourceType
		current.Actions = append([]string(nil), policy.Actions...)
		current.Effect = policy.Effect
		current.Description = policy.Description
		return s.UpdatePolicy(ctx, &current)
	}
	return nil
}

func splitGCPIdentityScope(scope string) (string, string, bool) {
	parts := strings.SplitN(strings.TrimSpace(scope), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	resourceType := strings.TrimSpace(parts[0])
	action := strings.TrimSpace(parts[1])
	return resourceType, action, resourceType != "" && action != ""
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}
