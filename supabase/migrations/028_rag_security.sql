-- 028_rag_security.sql
-- Phase E — RAG security: documents, chunks, classification, ACLs.
--
-- Access model (single source of truth: rag_can_read_document):
--   A caller can read a document iff they are an active member of the owning
--   organization AND the document's classification is at or below their
--   role-derived clearance AND (the document is 'public' OR they hold an
--   explicit grant — a user grant or a role grant matching their role).
--
--   Role -> max clearance: owner/admin/security = restricted,
--   developer = confidential, analyst = internal, viewer = public.
--
--   Clearance is a CEILING, not a pass: a 'restricted' document still needs
--   an explicit grant even for a restricted-clearance caller (defense in
--   depth). Grants are managed by owner/admin/security only.
--
--   Embeddings are stored as real[] and similarity is computed in the edge
--   function over the SQL-filtered candidate set only — retrieval NEVER
--   ranks on similarity before the tenant/clearance/grant filter. The
--   brute-force cosine scan is exact but O(candidates); pgvector is the
--   documented scale path, not a silent requirement (keeps this migration
--   extension-free and testable).

-- Classification rank: public < internal < confidential < restricted ----------
create or replace function public.rag_clearance_rank(level text)
returns integer
language sql
immutable
set search_path = public
as $$
  select case level
    when 'public' then 0
    when 'internal' then 1
    when 'confidential' then 2
    when 'restricted' then 3
    else null
  end;
$$;

-- Role -> maximum clearance ----------------------------------------------------
create or replace function public.rag_role_max_clearance(role text)
returns text
language sql
immutable
set search_path = public
as $$
  select case role
    when 'owner' then 'restricted'
    when 'admin' then 'restricted'
    when 'security' then 'restricted'
    when 'developer' then 'confidential'
    when 'analyst' then 'internal'
    else 'public'
  end;
$$;

-- Tables ----------------------------------------------------------------------
create table public.rag_documents (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  title text not null,
  classification text not null default 'internal'
    check (public.rag_clearance_rank(classification) is not null),
  source text,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.rag_chunks (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  document_id uuid not null references public.rag_documents(id) on delete cascade,
  chunk_index integer not null,
  content text not null,
  -- real[] keeps the migration extension-free; similarity runs in the edge
  -- function over filtered candidates only (see rag_search_candidates).
  embedding real[],
  embedding_model text,
  created_at timestamptz not null default now(),
  unique (document_id, chunk_index)
);

create table public.rag_grants (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  document_id uuid not null references public.rag_documents(id) on delete cascade,
  grantee_user_id uuid references auth.users(id) on delete cascade,
  grantee_role text check (grantee_role in ('owner', 'admin', 'security', 'developer', 'analyst', 'viewer')),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  check (grantee_user_id is not null or grantee_role is not null),
  unique (document_id, grantee_user_id),
  unique (document_id, grantee_role)
);

create index rag_documents_org_idx on public.rag_documents (organization_id);
create index rag_chunks_doc_idx on public.rag_chunks (document_id);
create index rag_chunks_org_idx on public.rag_chunks (organization_id);
create index rag_grants_doc_idx on public.rag_grants (document_id);

-- Single source of truth for document visibility --------------------------------
-- Security definer so RLS policies and the retrieval RPC share one
-- implementation; it re-checks membership on every call (stable, not a
-- cached session value).
create or replace function public.rag_can_read_document(p_document_id uuid)
returns boolean
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_doc public.rag_documents%rowtype;
  v_role text;
begin
  select * into v_doc from public.rag_documents where id = p_document_id;
  if not found then
    return false;
  end if;
  if not public.is_org_member(v_doc.organization_id) then
    return false;
  end if;
  v_role := public.org_role(v_doc.organization_id);
  -- Clearance ceiling.
  if public.rag_clearance_rank(v_doc.classification)
     > public.rag_clearance_rank(public.rag_role_max_clearance(v_role)) then
    return false;
  end if;
  -- Public documents are visible to every member within their clearance.
  if v_doc.classification = 'public' then
    return true;
  end if;
  -- Otherwise an explicit grant is required.
  return exists (
    select 1
    from public.rag_grants g
    where g.document_id = v_doc.id
      and (g.grantee_user_id = auth.uid() or g.grantee_role = v_role)
  );
end;
$$;

-- Retrieval candidate RPC -------------------------------------------------------
-- Returns the SECURITY-FILTERED candidate set for one organization. Similarity
-- ranking happens in the edge function over exactly these rows — never before.
-- The caller passes their clearance, but the function caps it at the
-- role-derived maximum, so a direct RPC call cannot escalate clearance.
create or replace function public.rag_search_candidates(
  p_organization_id uuid,
  p_clearance text,
  p_limit integer default 500
)
returns table (
  chunk_id uuid,
  document_id uuid,
  chunk_index integer,
  content text,
  embedding real[],
  embedding_model text,
  classification text,
  title text
)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_role text;
  v_effective_rank integer;
begin
  if not public.is_org_member(p_organization_id) then
    raise exception 'not a member of this organization';
  end if;
  v_role := public.org_role(p_organization_id);
  -- Cap the requested clearance at the role-derived maximum.
  v_effective_rank := least(
    coalesce(public.rag_clearance_rank(p_clearance), -1),
    public.rag_clearance_rank(public.rag_role_max_clearance(v_role))
  );
  if v_effective_rank < 0 then
    raise exception 'invalid clearance';
  end if;

  return query
  select
    c.id, c.document_id, c.chunk_index, c.content,
    c.embedding, c.embedding_model, d.classification, d.title
  from public.rag_chunks c
  join public.rag_documents d on d.id = c.document_id
  where c.organization_id = p_organization_id
    and public.rag_clearance_rank(d.classification) <= v_effective_rank
    and (
      d.classification = 'public'
      or exists (
        select 1
        from public.rag_grants g
        where g.document_id = d.id
          and (g.grantee_user_id = auth.uid() or g.grantee_role = v_role)
      )
    )
  order by c.document_id, c.chunk_index
  limit greatest(1, least(coalesce(p_limit, 500), 2000));
end;
$$;

-- RLS ---------------------------------------------------------------------------
alter table public.rag_documents enable row level security;
alter table public.rag_chunks enable row level security;
alter table public.rag_grants enable row level security;

-- Reads: the shared visibility check (clearance ceiling + grants).
create policy rag_documents_select on public.rag_documents
  for select using (public.rag_can_read_document(id));
create policy rag_chunks_select on public.rag_chunks
  for select using (public.rag_can_read_document(document_id));
create policy rag_grants_select on public.rag_grants
  for select using (public.rag_can_read_document(document_id));

-- Writes: ingestion roles (owner/admin/security/developer) for documents and
-- chunks; grants are managed by owner/admin/security only.
create policy rag_documents_insert on public.rag_documents
  for insert with check (
    public.has_org_role(organization_id, array['owner', 'admin', 'security', 'developer'])
  );
create policy rag_documents_update on public.rag_documents
  for update using (
    public.has_org_role(organization_id, array['owner', 'admin', 'security', 'developer'])
  );
create policy rag_documents_delete on public.rag_documents
  for delete using (
    public.has_org_role(organization_id, array['owner', 'admin', 'security'])
  );

create policy rag_chunks_insert on public.rag_chunks
  for insert with check (
    public.has_org_role(organization_id, array['owner', 'admin', 'security', 'developer'])
  );
create policy rag_chunks_delete on public.rag_chunks
  for delete using (
    public.has_org_role(organization_id, array['owner', 'admin', 'security'])
  );

create policy rag_grants_insert on public.rag_grants
  for insert with check (
    public.has_org_role(organization_id, array['owner', 'admin', 'security'])
  );
create policy rag_grants_delete on public.rag_grants
  for delete using (
    public.has_org_role(organization_id, array['owner', 'admin', 'security'])
  );

grant execute on function public.rag_clearance_rank(text) to authenticated;
grant execute on function public.rag_role_max_clearance(text) to authenticated;
grant execute on function public.rag_can_read_document(uuid) to authenticated;
grant execute on function public.rag_search_candidates(uuid, text, integer) to authenticated;
