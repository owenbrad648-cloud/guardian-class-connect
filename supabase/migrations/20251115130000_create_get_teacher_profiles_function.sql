CREATE OR REPLACE FUNCTION public.get_teacher_profiles()
RETURNS SETOF public.profiles
LANGUAGE sql
STABLE
AS $$
  SELECT p.*
  FROM public.profiles p
  JOIN public.user_roles ur ON p.id = ur.user_id
  WHERE ur.role = 'teacher';
$$;
