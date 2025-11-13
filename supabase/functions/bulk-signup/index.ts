// supabase/functions/bulk-signup/index.ts

import { createClient, SupabaseClient } from 'npm:@supabase/supabase-js@2'
import { corsHeaders } from '../_shared/cors.ts'
import { z } from 'npm:zod@3'

// Helper function to create Supabase client
function getSupabaseAdminClient(): SupabaseClient {
  const supabaseUrl = Deno.env.get('SUPABASE_URL');
  const supabaseServiceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');

  if (!supabaseUrl || !supabaseServiceRoleKey) {
    console.error("[Bulk Signup] CRITICAL: Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY environment variables.");
    throw new Error("پیکربندی سرور ناقص است. لطفاً با مدیر سیستم تماس بگیرید.");
  }
  return createClient(
    supabaseUrl,
    supabaseServiceRoleKey,
    { auth: { persistSession: false } } // Essential for Edge Functions
  );
}

// Input validation schemas
const userSchema = z.object({
  email: z.string().trim().email({ message: "Invalid email format" }).max(255, { message: "Email too long" }),
  full_name: z.string().trim().min(1, { message: "Full name is required" }).max(100, { message: "Full name too long" }),
  password: z.string().min(8, { message: "Password must be at least 8 characters" }).max(128, { message: "Password too long" }),
  temp_student_name: z.string().optional(),
});

const requestSchema = z.object({
  users: z.array(userSchema).min(1, { message: "At least one user required" }).max(50, { message: "Maximum 50 users per request" }),
  userType: z.enum(['admin', 'teacher', 'parent'], { message: "Invalid user type" }),
});

// Rate limiting helper
async function checkRateLimit(supabaseAdmin: SupabaseClient, userId: string): Promise<{ allowed: boolean; message?: string }> {
  const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
  
  const { data: recentAttempts, error } = await supabaseAdmin
    .from('bulk_signup_attempts')
    .select('id')
    .eq('user_id', userId)
    .gte('created_at', fiveMinutesAgo);

  if (error) {
    console.error('[Rate Limit] Error checking attempts:', error);
    return { allowed: true };
  }

  const attemptCount = recentAttempts?.length || 0;
  const maxAttempts = 3; 

  if (attemptCount >= maxAttempts) {
    return { 
      allowed: false, 
      message: `درخواست‌های بیش از حد. لطفاً ${5} دقیقه صبر کنید و دوباره تلاش کنید.` 
    };
  }

  return { allowed: true };
}

async function logAttempt(supabaseAdmin: SupabaseClient, userId: string, userCount: number) {
  await supabaseAdmin
    .from('bulk_signup_attempts')
    .insert({
      user_id: userId,
      user_count: userCount,
    });
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }

  let supabaseAdmin: SupabaseClient;
  try {
     supabaseAdmin = getSupabaseAdminClient();
  } catch (initError: unknown) {
      const errorMsg = initError instanceof Error ? initError.message : String(initError);
      return new Response(JSON.stringify({ success: false, error: errorMsg, errors: [errorMsg] }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 500,
      });
  }

  try {
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) {
      return new Response(JSON.stringify({ success: false, error: 'Unauthorized - Missing authentication token' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 401,
      });
    }

    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error: authError } = await supabaseAdmin.auth.getUser(token);
    
    if (authError || !user) {
      return new Response(JSON.stringify({ success: false, error: 'Unauthorized - Invalid token' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 401,
      });
    }

    const { data: roleData } = await supabaseAdmin
      .from('user_roles')
      .select('role')
      .eq('user_id', user.id)
      .eq('role', 'admin')
      .single();

    if (!roleData) {
      return new Response(JSON.stringify({ success: false, error: 'Forbidden - Admin access required' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 403,
      });
    }

    const rateLimitResult = await checkRateLimit(supabaseAdmin, user.id);
    if (!rateLimitResult.allowed) {
      return new Response(JSON.stringify({ success: false, error: rateLimitResult.message }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 429,
      });
    }

    const body = await req.json();
    
    const validationResult = requestSchema.safeParse(body);
    if (!validationResult.success) {
      const errors = validationResult.error.errors.map(e => `${e.path.join('.')}: ${e.message}`);
      return new Response(JSON.stringify({ success: false, error: 'Input validation failed', errors }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 400,
      });
    }

    const { users, userType } = validationResult.data;
    await logAttempt(supabaseAdmin, user.id, users.length);

    const errors: string[] = [];
    const results: { email: string; id: string; temp_student_name?: string }[] = [];
    let successCount = 0;

    for (const [index, user] of users.entries()) {
      const rowIndex = index + 1;
      let userId = '';
      const { email, password, full_name, temp_student_name } = user; // Removed username
      const logPrefix = `[Bulk Signup] User ${rowIndex}/${users.length} (${email || 'No Email'}):`;

      try {
        const { data: authData, error: authError } = await supabaseAdmin.auth.admin.createUser({
          email: email,
          password: password,
          email_confirm: true,
          user_metadata: { full_name: full_name }, // Removed username
        });

        if (authError) {
          if (authError.message.includes('already registered') || authError.message.includes('unique constraint')) {
             throw new Error(`(ردیف ${rowIndex}: ${email}): ایمیل قبلا در سیستم احراز هویت ثبت شده است.`);
          }
          if (authError.message.includes('Database error')) {
             throw new Error(`(ردیف ${rowIndex}: ${email}) - خطای پایگاه داده هنگام ایجاد کاربر Auth: ${authError.message}`);
          }
          throw new Error(`(ردیف ${rowIndex}: ${email}) - خطا در ساخت کاربر Auth: ${authError.message}`);
        }

        userId = authData.user.id;

        // Note: The handle_new_user trigger should be creating the profile automatically.
        // This explicit insert is kept as a fallback/explicit step, but we remove the username column.
        const { error: profileInsertError } = await supabaseAdmin
            .from('profiles')
            .insert({
                id: userId,
                full_name: full_name,
                email: email
                // username column removed
            });

        if (profileInsertError) {
            // Check if the error is because the trigger already created the profile.
            // A "duplicate key" error (23505) on the primary key is okay in this context.
            if (profileInsertError.code !== '23505' || !profileInsertError.message.includes('profiles_pkey')) {
               if (profileInsertError.code === '23505' && profileInsertError.message.includes('profiles_email_key')) {
                   throw new Error(`(ردیف ${rowIndex}: ${email}) - خطا در ساخت پروفایل: ایمیل '${email}' از قبل در جدول پروفایل‌ها وجود دارد.`);
               }
              throw new Error(`(ردیف ${rowIndex}: ${email}) - خطا در ساخت پروفایل: ${profileInsertError.message}`);
            }
        }
        
        const { error: roleError } = await supabaseAdmin.from('user_roles').insert({
            user_id: userId,
            role: userType,
        });

        if (roleError) {
             if (roleError.code === '23502' && roleError.message.includes('"role" violates not-null constraint')) {
                 throw new Error(`(ردیف ${rowIndex}: ${email}) - خطا در تخصیص نقش: مقدار نقش (role) نامعتبر یا null ارسال شده است.`);
             }
             throw new Error(`(ردیف ${rowIndex}: ${email}) - خطا در تخصیص نقش '${userType}': ${roleError.message}`);
        }

        if (userType === 'teacher') {
          const { error: teacherError } = await supabaseAdmin.from('teachers').insert({
            profile_id: userId,
          });
          if (teacherError) {
             throw new Error(`(ردیف ${rowIndex}: ${email}) - خطا در ساخت رکورد معلم: ${teacherError.message}`);
          }
        }

        results.push({ email, id: userId, temp_student_name });
        successCount++;

      } catch (userError: unknown) {
        const errorMsg = userError instanceof Error ? userError.message : String(userError);
        errors.push(errorMsg);

        if (userId) {
          try {
            await supabaseAdmin.auth.admin.deleteUser(userId);
          } catch (rollbackException: unknown) {
            const rollbackMsg = rollbackException instanceof Error ? rollbackException.message : String(rollbackException);
            errors.push(`(ردیف ${rowIndex}: ${email}) - استثنا در حین بازگردانی عملیات: ${rollbackMsg}`);
          }
        }
      }
    }

    const overallSuccess = errors.length === 0 && users.length > 0;
    return new Response(JSON.stringify({
      success: overallSuccess,
      successCount,
      errors,
      results
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      status: 200,
    });

  } catch (error: unknown) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    return new Response(JSON.stringify({
      success: false,
      error: `خطای کلی در فانکشن: ${errorMsg}`,
      errors: [errorMsg]
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      status: error instanceof SyntaxError ? 400 : 500,
    });
  }
});
