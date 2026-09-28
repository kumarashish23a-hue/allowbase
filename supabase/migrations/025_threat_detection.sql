-- 025_threat_detection.sql
-- Adds the `threat.category` policy condition so rules can target attack
-- patterns found by the deterministic threat detectors (threat-v1):
-- prompt_injection, jailbreak, system_prompt_extraction, exfiltration_attempt,
-- malicious_instruction, suspicious_tool_call.
--
-- Threat findings travel inside p_content_findings alongside content findings
-- (same JSON shape: detector/category/severity/confidence/count), but this
-- branch only matches findings whose detector starts with 'threat-', so a
-- content.category rule can never accidentally match a threat category and
-- vice versa. Unknown fields still fail closed (never match).

drop function if exists public.policy_condition_matches(text, text, jsonb, uuid, uuid[], public.ai_models, text, jsonb);

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
    -- Threat findings (detector 'threat-*') are skipped here; they are
    -- matched by the threat.category branch below.
    for v_finding_cat in
      select f ->> 'category'
      from jsonb_array_elements(coalesce(p_content_findings, '[]'::jsonb)) f
      where coalesce(f ->> 'detector', '') not like 'threat-%'
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

  elsif p_field = 'threat.category' then
    -- Matches when ANY threat-detector finding's category matches the value.
    -- Only findings stamped by a threat detector (detector 'threat-*') are
    -- considered, so content findings can never satisfy this branch.
    for v_finding_cat in
      select f ->> 'category'
      from jsonb_array_elements(coalesce(p_content_findings, '[]'::jsonb)) f
      where coalesce(f ->> 'detector', '') like 'threat-%'
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
      -- A threat condition matches when ANY threat finding matches it.
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
