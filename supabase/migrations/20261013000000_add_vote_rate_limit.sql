create table if not exists public.vote_rate_limits (
  ip_hash text primary key,
  window_started_at timestamptz not null default now(),
  attempts integer not null default 0,
  updated_at timestamptz not null default now()
);
alter table public.vote_rate_limits enable row level security;
revoke all on public.vote_rate_limits from anon, authenticated, public;
grant all on public.vote_rate_limits to service_role;

create or replace function public.consume_vote_rate_limit(
  p_ip_hash text,
  p_limit integer default 5,
  p_window_seconds integer default 3600
) returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_attempts integer;
begin
  if p_ip_hash is null or length(p_ip_hash) < 32 or p_limit < 1 or p_window_seconds < 1 then
    return false;
  end if;

  insert into public.vote_rate_limits as current_limit
    (ip_hash, window_started_at, attempts, updated_at)
  values (p_ip_hash, now(), 1, now())
  on conflict (ip_hash) do update
  set attempts = case
        when current_limit.window_started_at <= now() - make_interval(secs => p_window_seconds) then 1
        else current_limit.attempts + 1
      end,
      window_started_at = case
        when current_limit.window_started_at <= now() - make_interval(secs => p_window_seconds) then now()
        else current_limit.window_started_at
      end,
      updated_at = now()
  returning attempts into v_attempts;

  return v_attempts <= p_limit;
end;
$$;

revoke all on function public.consume_vote_rate_limit(text, integer, integer) from public, anon, authenticated;
grant execute on function public.consume_vote_rate_limit(text, integer, integer) to service_role;
