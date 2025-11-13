import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders } from "../_shared/cors.ts";

// This function implements a secure login flow using username and password.
// It uses the service_role key to look up a user's email from their username
// in a 'profiles' table, and then uses the anon key to sign them in.

serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    // 1. Check for required Supabase environment variables
    const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
    const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY");
    const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

    if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_ROLE_KEY) {
      throw new Error("متغیرهای محیطی پروژه Supabase به درستی تنظیم نشده‌اند.");
    }

    // 2. Parse request body
    const { username, password } = await req.json();
    if (!username || !password) {
      throw new Error("نام کاربری و رمز عبور الزامی است.");
    }

    // 3. Initialize Admin Client to bypass RLS
    const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

    // 4. Find the user's email from their username in the 'profiles' table
    const { data: profile, error: profileError } = await supabaseAdmin
      .from("profiles")
      .select("email")
      .eq("username", username)
      .single();

    // Handle profile lookup errors (e.g., user not found)
    if (profileError || !profile) {
      // Use a generic error message for security to prevent username enumeration
      throw new Error("نام کاربری یا رمز عبور اشتباه است.");
    }

    // 5. Initialize Public Client and attempt to sign in
    const supabaseClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
    const { data: authData, error: authError } = await supabaseClient.auth.signInWithPassword({
      email: profile.email,
      password: password,
    });

    // Handle authentication errors (e.g., wrong password)
    if (authError) {
      throw new Error("نام کاربری یا رمز عبور اشتباه است.");
    }

    // 6. Return the complete session data on success
    return new Response(JSON.stringify({ success: true, ...authData }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      status: 200,
    });

  } catch (error) {
    // 7. Catch any other errors and return a generic failure response
    console.error("Login Function Error:", error.message);
    return new Response(JSON.stringify({ success: false, error: error.message }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      status: 400,
    });
  }
});
