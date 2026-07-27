-- ============================================================
-- Evaluación de Desempeño 180° — Etinar S.A.
-- Esquema de base de datos para Supabase (PostgreSQL)
-- Pegar TODO este contenido en Supabase → SQL Editor → Run
-- ============================================================

-- 1) PERFILES: un registro por cada usuario (admin, evaluador, evaluado)
create table if not exists public.perfiles (
  id           uuid primary key references auth.users(id) on delete cascade,
  usuario      text unique not null,
  nombre       text,
  rol          text not null check (rol in ('admin','evaluador','evaluado')),
  departamento text,
  puesto       text,
  creado_en    timestamptz default now()
);

-- 2) PUESTOS: cada puesto puede tener sus propias competencias
create table if not exists public.puestos (
  id           bigint generated always as identity primary key,
  nombre       text not null,
  departamento text,
  creado_en    timestamptz default now()
);

-- 3) COMPETENCIAS: los ítems a evaluar, agrupados por categoría, por puesto
create table if not exists public.competencias (
  id        bigint generated always as identity primary key,
  puesto_id bigint references public.puestos(id) on delete cascade,
  categoria text not null,           -- ej. "Trabajo en equipo", "Comunicación"
  texto     text not null,           -- el enunciado a calificar
  orden     int default 0
);

-- 4) EVALUACIONES: cada asignación de evaluación (evaluador->evaluado o autoevaluación)
create table if not exists public.evaluaciones (
  id           bigint generated always as identity primary key,
  evaluado_id  uuid references public.perfiles(id) on delete cascade,
  evaluador_id uuid references public.perfiles(id) on delete cascade,
  puesto_id    bigint references public.puestos(id),
  codificacion text,
  fecha        date default current_date,
  tipo         text not null default 'evaluador' check (tipo in ('evaluador','autoevaluacion')),
  estado       text not null default 'pendiente' check (estado in ('pendiente','completada')),
  creado_en    timestamptz default now()
);

-- 5) RESPUESTAS: el puntaje 1-5 para cada competencia dentro de una evaluación
create table if not exists public.respuestas (
  id             bigint generated always as identity primary key,
  evaluacion_id  bigint references public.evaluaciones(id) on delete cascade,
  competencia_id bigint references public.competencias(id) on delete cascade,
  puntaje        int check (puntaje between 1 and 5),
  unique (evaluacion_id, competencia_id)
);

-- 6) COMENTARIOS: fortalezas, áreas de mejora y aspectos del evaluador
create table if not exists public.comentarios (
  id                          bigint generated always as identity primary key,
  evaluacion_id               bigint unique references public.evaluaciones(id) on delete cascade,
  fortalezas                  text,
  areas_mejora                text,
  aspectos_mejorar_evaluador  text
);

-- ============================================================
-- FUNCIÓN AUXILIAR: devuelve el rol del usuario que está conectado
-- (security definer evita recursión al leer la tabla perfiles)
-- ============================================================
create or replace function public.mi_rol()
returns text
language sql
security definer
stable
as $$
  select rol from public.perfiles where id = auth.uid()
$$;

-- ============================================================
-- SEGURIDAD (RLS): activar y definir quién puede ver/editar qué
-- ============================================================
alter table public.perfiles     enable row level security;
alter table public.puestos      enable row level security;
alter table public.competencias enable row level security;
alter table public.evaluaciones enable row level security;
alter table public.respuestas   enable row level security;
alter table public.comentarios  enable row level security;

-- PERFILES: cualquier usuario conectado puede ver la lista; solo admin modifica
drop policy if exists perfiles_select on public.perfiles;
create policy perfiles_select on public.perfiles
  for select using (auth.role() = 'authenticated');
drop policy if exists perfiles_admin on public.perfiles;
create policy perfiles_admin on public.perfiles
  for all using (public.mi_rol() = 'admin') with check (public.mi_rol() = 'admin');

-- PUESTOS: todos ven; solo admin modifica
drop policy if exists puestos_select on public.puestos;
create policy puestos_select on public.puestos
  for select using (auth.role() = 'authenticated');
drop policy if exists puestos_admin on public.puestos;
create policy puestos_admin on public.puestos
  for all using (public.mi_rol() = 'admin') with check (public.mi_rol() = 'admin');

-- COMPETENCIAS: todos ven; solo admin modifica
drop policy if exists competencias_select on public.competencias;
create policy competencias_select on public.competencias
  for select using (auth.role() = 'authenticated');
drop policy if exists competencias_admin on public.competencias;
create policy competencias_admin on public.competencias
  for all using (public.mi_rol() = 'admin') with check (public.mi_rol() = 'admin');

-- EVALUACIONES: admin ve todo; cada quien ve las suyas (como evaluador o evaluado)
drop policy if exists evaluaciones_ver on public.evaluaciones;
create policy evaluaciones_ver on public.evaluaciones
  for select using (
    public.mi_rol() = 'admin'
    or evaluador_id = auth.uid()
    or evaluado_id = auth.uid()
  );
drop policy if exists evaluaciones_admin on public.evaluaciones;
create policy evaluaciones_admin on public.evaluaciones
  for all using (public.mi_rol() = 'admin') with check (public.mi_rol() = 'admin');
-- el evaluador/evaluado asignado puede actualizar el estado de su evaluación
drop policy if exists evaluaciones_update_propia on public.evaluaciones;
create policy evaluaciones_update_propia on public.evaluaciones
  for update using (evaluador_id = auth.uid() or evaluado_id = auth.uid());

-- RESPUESTAS: se puede ver/editar si la evaluación pertenece al usuario (o es admin)
drop policy if exists respuestas_todo on public.respuestas;
create policy respuestas_todo on public.respuestas
  for all using (
    public.mi_rol() = 'admin'
    or exists (
      select 1 from public.evaluaciones e
      where e.id = respuestas.evaluacion_id
        and (e.evaluador_id = auth.uid() or e.evaluado_id = auth.uid())
    )
  ) with check (
    public.mi_rol() = 'admin'
    or exists (
      select 1 from public.evaluaciones e
      where e.id = respuestas.evaluacion_id
        and (e.evaluador_id = auth.uid() or e.evaluado_id = auth.uid())
    )
  );

-- COMENTARIOS: misma regla que respuestas
drop policy if exists comentarios_todo on public.comentarios;
create policy comentarios_todo on public.comentarios
  for all using (
    public.mi_rol() = 'admin'
    or exists (
      select 1 from public.evaluaciones e
      where e.id = comentarios.evaluacion_id
        and (e.evaluador_id = auth.uid() or e.evaluado_id = auth.uid())
    )
  ) with check (
    public.mi_rol() = 'admin'
    or exists (
      select 1 from public.evaluaciones e
      where e.id = comentarios.evaluacion_id
        and (e.evaluador_id = auth.uid() or e.evaluado_id = auth.uid())
    )
  );

-- ============================================================
-- LISTO. Estas tablas guardan usuarios, puestos, competencias,
-- evaluaciones, respuestas y comentarios, con seguridad por rol.
-- ============================================================
