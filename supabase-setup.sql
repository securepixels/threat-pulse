-- Run this in your Supabase SQL editor
create table if not exists lookups (
  id uuid default gen_random_uuid() primary key,
  indicator text not null,
  type text not null,
  verdict text not null,
  confidence int default 0,
  raw_data jsonb,
  created_at timestamptz default now()
);
alter table lookups enable row level security;
create policy "Public read" on lookups for select using (true);
create policy "Public insert" on lookups for insert with check (true);
