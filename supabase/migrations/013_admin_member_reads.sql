-- 013_admin_member_reads.sql
-- Let workspace owners/admins read the profiles (names) of members in the
-- organizations they administer, so the admin panel can list who is in a client.
-- Everyone else keeps the own-profile-only rule from 007.

create policy "profiles_select_org_admin"
  on public.profiles for select
  using (
    exists (
      select 1
      from public.organization_members m
      where m.user_id = profiles.id
        and m.status = 'active'
        and public.has_org_role(m.organization_id, array['owner', 'admin'])
    )
  );
