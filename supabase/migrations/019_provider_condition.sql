-- 019_provider_condition.sql
-- Adds the `ai.provider` policy condition so rules can target a specific AI
-- provider (e.g. openai for ChatGPT). Matching is case-insensitive because
-- existing provider values are free text ('OpenAI', 'Anthropic', 'Internal').
-- Unknown fields still fail closed (never match).

-- 2. policy_condition_matches: content.category --------------------------------
drop function if exists public.policy_condition_matches(text, text, jsonb, uuid, uuid[], public.ai_models, text);

create or replace function public.policy_condition_matches(
  p_field text,
  p_operator text,
  p_value jsonb,
  p_org_id uuid,
  p_asset_ids uuid[],
  p_model public.ai_models,
  p_purpose text,
  p_content_findings jsonb
)
returns boolean
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_asset_val text;
  v_asset_match boolean;
  v_finding_cat text;
  v_cat_match boolean;
  v_scalar text := (p_value #>> '{}');
begin
  if p_field in ('data.classification', 'data.sensitivity_level') then
    for v_asset_val in
      select
        case
          when p_field = 'data.classification' then a.classification
          else a.sensitivity_level
        end
      from public.data_assets a
      where a.id = any (p_asset_ids)
        and a.organization_id = p_org_id
    loop
      v_asset_match := false;
      if p_operator = 'equals' then
        v_asset_match := (v_asset_val = v_scalar);
      elsif p_operator = 'not_equals' then
        v_asset_match := (v_asset_val <> v_scalar);
      elsif p_operator = 'in' then
        select exists(
          select 1 from jsonb_array_elements_text(p_value) t where t = v_asset_val
        ) into v_asset_match;
      elsif p_operator = 'not_in' then
        select not exists(
          select 1 from jsonb_array_elements_text(p_value) t where t = v_asset_val
        ) into v_asset_match;
      end if;
      -- A data condition matches when ANY requested asset matches it.
      if v_asset_match then
        return true;
      end if;
    end loop;
    return false;

  elsif p_field = 'ai.is_external' then
    if p_operator = 'equals' then
      return p_model.is_external = (v_scalar::boolean);
    elsif p_operator = 'not_equals' then
      return p_model.is_external <> (v_scalar::boolean);
    else
      return false;
    end if;

  elsif p_field = 'ai.is_approved' then
    if p_operator = 'equals' then
      return p_model.is_approved = (v_scalar::boolean);
    elsif p_operator = 'not_equals' then
      return p_model.is_approved <> (v_scalar::boolean);
    else
      return false;
    end if;

  elsif p_field = 'ai.provider' then
    -- Case-insensitive: 'OpenAI', 'openai', and 'OPENAI' all match.
    if p_operator = 'equals' then
      return lower(coalesce(p_model.provider, '')) = lower(v_scalar);
    elsif p_operator = 'not_equals' then
      return lower(coalesce(p_model.provider, '')) <> lower(v_scalar);
    elsif p_operator = 'in' then
      select exists(
        select 1 from jsonb_array_elements_text(p_value) t
        where lower(t) = lower(coalesce(p_model.provider, ''))
      ) into v_asset_match;
      return v_asset_match;
    elsif p_operator = 'not_in' then
      select not exists(
        select 1 from jsonb_array_elements_text(p_value) t
        where lower(t) = lower(coalesce(p_model.provider, ''))
      ) into v_asset_match;
      return v_asset_match;
    else
      return false;
    end if;

  elsif p_field = 'purpose' then
    if p_operator = 'equals' then
      return lower(coalesce(p_purpose, '')) = lower(v_scalar);
    elsif p_operator = 'not_equals' then
      return lower(coalesce(p_purpose, '')) <> lower(v_scalar);
    elsif p_operator = 'in' then
      select exists(
        select 1 from jsonb_array_elements_text(p_value) t
        where lower(t) = lower(coalesce(p_purpose, ''))
      ) into v_asset_match;
      return v_asset_match;
    else
      return false;
    end if;

  elsif p_field = 'content.category' then
    -- Matches when ANY content finding's category matches the value.
    -- Findings are produced by the edge-function detectors (never raw text).
    for v_finding_cat in
      select f ->> 'category'
      from jsonb_array_elements(coalesce(p_content_findings, '[]'::jsonb)) f
    loop
      v_cat_match := false;
      if p_operator = 'equals' then
        v_cat_match := (v_finding_cat = v_scalar);
      elsif p_operator = 'not_equals' then
        v_cat_match := (v_finding_cat <> v_scalar);
      elsif p_operator = 'in' then
        select exists(
          select 1 from jsonb_array_elements_text(p_value) t where t = v_finding_cat
        ) into v_cat_match;
      elsif p_operator = 'not_in' then
        select not exists(
          select 1 from jsonb_array_elements_text(p_value) t where t = v_finding_cat
        ) into v_cat_match;
      end if;
      -- A content condition matches when ANY finding matches it.
      if v_cat_match then
        return true;
      end if;
    end loop;
    return false;

  else
    -- Unknown fields never match (fail closed for policy authors to notice).
    return false;
  end if;
end;
$$;

grant execute on function public.policy_condition_matches(text, text, jsonb, uuid, uuid[], public.ai_models, text, jsonb) to authenticated;
