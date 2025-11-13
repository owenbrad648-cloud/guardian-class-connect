import { serve } from 'https://deno.land/std@0.177.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { corsHeaders } from '../_shared/cors.ts';

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }

  try {
    const supabase = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);

    const { email, password, full_name } = await req.json();

    if (!email || !password || !full_name) {
      return new Response(JSON.stringify({ error: 'Email, password, and full name are required.' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 400,
      });
    }

    // 1. Create a new user in auth.users
    const { data: userCreationData, error: userError } = await supabase.auth.admin.createUser({
      email: email,
      password: password,
      email_confirm: true, // Optionally, require email confirmation
    });

    if (userError) throw new Error(`Auth Error: ${userError.message}`);
    if (!userCreationData || !userCreationData.user) throw new Error('Failed to create user.');
    const userId = userCreationData.user.id;

    // 2. Insert into public.profiles
    const { error: profileError } = await supabase.from('profiles').insert({
      id: userId,
      full_name: full_name,
      email: email,
    });

    if (profileError) throw new Error(`Profile Error: ${profileError.message}`);

    // 3. Assign role in public.user_roles
    const { error: roleError } = await supabase.from('user_roles').insert({
      user_id: userId,
      role: 'teacher',
    });

    if (roleError) throw new Error(`Role Error: ${roleError.message}`);

    // 4. Insert into public.teachers
    const { error: teacherError } = await supabase.from('teachers').insert({
      profile_id: userId,
    });

    if (teacherError) throw new Error(`Teacher Error: ${teacherError.message}`);

    return new Response(JSON.stringify({ success: true, userId }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      status: 201,
    });

  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      status: 500,
    });
  }
});
