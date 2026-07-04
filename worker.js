export default {
  async fetch(request, env) {
    // 1. Define strict CORS headers
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*", // For maximum security later, change this to your frontend domain (e.g., "https://cupmail.qzz.io")
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Content-Type": "application/json"
    };

    // 2. Handle CORS Preflight Options Request
    if (request.method === "OPTIONS") {
      return new Response(null, { 
        status: 204,
        headers: corsHeaders 
      });
    }

    // 3. Reject any non-POST methods
    if (request.method !== "POST") {
      return new Response(JSON.stringify({ success: false, error: "Method not allowed" }), { 
        status: 405, 
        headers: corsHeaders 
      });
    }

    try {
      // 4. Parse incoming payload safely
      const body = await request.json().catch(() => ({}));
      const { email, domain, expires_at, user_id, turnstileToken } = body;

      // Validate required inputs
      if (!email || !domain || !expires_at || !user_id || !turnstileToken) {
        return new Response(JSON.stringify({ success: false, error: "Missing required parameters" }), { 
          status: 400, 
          headers: corsHeaders 
        });
      }

      // 5. Verify Turnstile Token with Cloudflare Server-Side API
      const clientIp = request.headers.get("CF-Connecting-IP");
      const turnstileFormData = new FormData();
      turnstileFormData.append("secret", env.TURNSTILE_SECRET_KEY);
      turnstileFormData.append("response", turnstileToken);
      if (clientIp) {
        turnstileFormData.append("remoteip", clientIp);
      }

      const turnstileResponse = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
        method: "POST",
        body: turnstileFormData
      });
      
      const turnstileResult = await turnstileResponse.json();
      
      if (!turnstileResult.success) {
        return new Response(JSON.stringify({ success: false, error: "CAPTCHA verification failed" }), { 
          status: 403, 
          headers: corsHeaders 
        });
      }

      // 6. Push payload securely to Supabase REST API using service_role bypass
      const supabaseResponse = await fetch(`${env.SUPABASE_URL}/rest/v1/addresses`, {
        method: "POST",
        headers: {
          "apikey": env.SUPABASE_SERVICE_KEY,
          "Authorization": `Bearer ${env.SUPABASE_SERVICE_KEY}`,
          "Content-Type": "application/json",
          "Prefer": "return=representation" // Tells Supabase to return the newly created row
        },
        body: JSON.stringify({
          email: email,
          domain: domain,
          expires_at: expires_at,
          user_id: user_id
        })
      });

      if (!supabaseResponse.ok) {
        const errorDetails = await supabaseResponse.text();
        console.error("Supabase Database Error:", errorDetails);
        return new Response(JSON.stringify({ success: false, error: "Database transaction failed" }), { 
          status: 500, 
          headers: corsHeaders 
        });
      }

      const databaseResult = await supabaseResponse.json();

      // 7. Return success outcome back to client frontend
      return new Response(JSON.stringify({ success: true, data: databaseResult }), { 
        status: 200,
        headers: corsHeaders 
      });

    } catch (err) {
      console.error("Global Worker Exception:", err.message);
      return new Response(JSON.stringify({ success: false, error: "Internal Server Error" }), { 
        status: 500, 
        headers: corsHeaders 
      });
    }
  }
};
