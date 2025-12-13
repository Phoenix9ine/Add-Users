import express from "express";
import cors from "cors";
import fetch from "node-fetch"; // keeps compatibility in some runtimes
import { createClient } from "@supabase/supabase-js";

const app = express();
app.use(cors());
app.use(express.json());

// --- Environment vars (must be set in Vercel)
// SUPABASE_URL
// SUPABASE_SERVICE_ROLE_KEY
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY environment variables.");
  // don't crash the process; respond with helpful error when endpoint called.
}

const adminSupabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
});

// Helper: safe-json
const safeJson = (obj) => {
  try { return JSON.stringify(obj); } catch (e) { return String(obj); }
};

app.post("/create-staff", async (req, res) => {
  try {
    // expected body: { admin_email, full_name, email, role }
    const { admin_email, full_name, email, role } = req.body ?? {};

    // basic validation
    if (!admin_email) {
      return res.status(400).json({ error: "admin_email is required" });
    }
    if (!email) {
      return res.status(400).json({ error: "staff email is required" });
    }
    if (!role) {
      return res.status(400).json({ error: "role is required (e.g. 'staff')" });
    }

    // --------- ADMIN CHECK (using service-role client to avoid RLS blocking) ---------
    // We use the adminSupabase (service role key) so we can read profiles regardless of RLS.
    const { data: adminData, error: adminError } = await adminSupabase
      .from("profiles")
      .select("id, hotel_id, role")
      .eq("email", admin_email)
      .maybeSingle();

    if (adminError) {
      console.error("Error fetching admin profile:", adminError);
      return res.status(500).json({ error: "Error verifying admin (db)", detail: adminError.message ?? adminError });
    }

    if (!adminData) {
      // admin email not found in profiles
      return res.status(403).json({ error: "Forbidden: Admin profile not found" });
    }

    if (adminData.role !== "admin" && adminData.role !== "super_admin") {
      return res.status(403).json({ error: "Forbidden: Not an admin" });
    }

    const hotel_id = adminData.hotel_id ?? null;

    // --------- CREATE USER IN AUTH (invite) ---------
    const { data: authData, error: authError } = await adminSupabase.auth.admin.createUser({
      email,
      email_confirm: false, // triggers an invite email
    });

    if (authError) {
      console.error("Auth createUser error:", authError);
      return res.status(400).json({ error: "Failed to create auth user", detail: authError.message ?? authError });
    }

    // If authData is missing, return error
    if (!authData || !authData.user || !authData.user.id) {
      console.error("Auth createUser returned no user:", safeJson(authData));
      return res.status(500).json({ error: "Auth user creation returned invalid response", detail: authData ?? null });
    }

    const newUserId = authData.user.id;

    // --------- INSERT PROFILE (with hotel_id and role) ---------
    const { error: profileInsertError } = await adminSupabase
  .from("profiles")
  .insert({
    id: newUserId,
    email,
    role,
    full_name,
    hotel_id,
  }, {
    returning: "minimal",
    force: true // <<< bypass all RLS policies safely when using service key
  });

    if (profileInsertError) {
      console.error("Profile insert failed for user:", newUserId, profileInsertError);

      // NOTE: we do NOT auto-delete the created auth user here to avoid accidental deletions.
      // We return the created user id so you can cleanup manually if desired.
      return res.status(500).json({
        error: "Failed to insert profile row after creating auth user",
        auth_user_id: newUserId,
        detail: profileInsertError.message ?? profileInsertError,
      });
    }

    // SUCCESS
    return res.status(200).json({
      success: true,
      user_id: newUserId,
      hotel_id,
      message: "Staff created (invite sent).",
    });
  } catch (err) {
    console.error("Unhandled server error:", err);
    return res.status(500).json({ error: "Server error", detail: err?.message ?? String(err) });
  }
});

// health check root -> simple message (helps to see GET / not failing)
app.get("/", (req, res) => {
  res.send("create-staff API is running. POST /create-staff to add staff.");
});

// --- Production listen (Vercel will ignore this in serverless env but local dev will use)
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
