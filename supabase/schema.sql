-- Execute este arquivo no SQL Editor do seu projeto Supabase.
-- As tabelas não têm políticas públicas: todo acesso acontece na Edge Function com service role.
create extension if not exists pgcrypto;

create table if not exists public.awards_config (
  id integer primary key check (id = 1),
  deadline timestamptz null,
  created_at timestamptz not null default now()
);
insert into public.awards_config (id, deadline) values (1, null) on conflict (id) do nothing;

create table if not exists public.students (
  id uuid primary key default gen_random_uuid(),
  full_name text not null,
  normalized_name text not null unique,
  ra_digest text not null,
  is_admin boolean not null default false,
  -- Os dois estágios têm cédulas independentes; não armazenamos a escolha junto ao aluno.
  has_voted boolean not null default false,
  has_voted_general boolean not null default false,
  has_voted_final boolean not null default false,
  created_at timestamptz not null default now()
);
-- Migração segura caso a tabela já tenha sido criada pela versão anterior.
alter table public.students add column if not exists has_voted_general boolean not null default false;
alter table public.students add column if not exists has_voted_final boolean not null default false;
update public.students set has_voted_general = true where has_voted = true and has_voted_general = false;

-- Cédulas sem identificador de participante: a tabela de votos não armazena student_id.
create table if not exists public.ballots (
  ballot_id uuid primary key default gen_random_uuid(),
  phase text not null default 'general' check (phase in ('general','final')),
  votes jsonb not null default '{}'::jsonb,
  submitted_at timestamptz not null default now()
);

-- Recados individuais. O navegador nunca consulta esta tabela diretamente;
-- a Edge Function devolve somente o recado da pessoa autenticada.
create table if not exists public.student_messages (
  student_id uuid primary key references public.students(id) on delete cascade,
  message text not null,
  updated_at timestamptz not null default now()
);
-- Migração segura da versão anterior, em que as cédulas ainda não tinham fase.
alter table public.ballots add column if not exists phase text not null default 'general';
do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'ballots_phase_check') then
    alter table public.ballots add constraint ballots_phase_check check (phase in ('general','final'));
  end if;
end $$;

-- Controla um voto em cada fase dentro de uma transação. A cédula não guarda o ID do votante.
drop function if exists public.submit_anonymous_ballot(uuid, jsonb);
create or replace function public.submit_anonymous_ballot(p_student_id uuid, p_votes jsonb, p_phase text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_deadline timestamptz;
  v_current_phase text;
begin
  select deadline into v_deadline from public.awards_config where id = 1 for update;
  if v_deadline is null then raise exception 'A votação ainda não foi aberta pela organização.'; end if;
  if now() >= v_deadline then raise exception 'O prazo de votação terminou.'; end if;
  if now() < v_deadline - interval '10 days' then
    v_current_phase := 'general';
  else
    v_current_phase := 'final';
  end if;
  if p_phase not in ('general','final') or p_phase <> v_current_phase then
    raise exception 'A fase da votação mudou. Atualize a página e vote na fase atual.';
  end if;
  if p_phase = 'general' then
    update public.students set has_voted_general = true
      where id = p_student_id and has_voted_general = false;
  else
    update public.students set has_voted_final = true
      where id = p_student_id and has_voted_final = false;
  end if;
  if not found then raise exception 'Esta conta já enviou uma cédula nesta fase.'; end if;
  insert into public.ballots(phase, votes) values (p_phase, p_votes);
end;
$$;
revoke all on function public.submit_anonymous_ballot(uuid, jsonb, text) from public, anon, authenticated;
grant execute on function public.submit_anonymous_ballot(uuid, jsonb, text) to service_role;

alter table public.awards_config enable row level security;
alter table public.students enable row level security;
alter table public.ballots enable row level security;
alter table public.student_messages enable row level security;

revoke all on table public.awards_config from anon, authenticated;
revoke all on table public.students from anon, authenticated;
revoke all on table public.ballots from anon, authenticated;
revoke all on table public.student_messages from anon, authenticated;
-- Não crie políticas RLS públicas para essas tabelas. A Edge Function usa service_role.
