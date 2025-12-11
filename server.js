import express from "express";
import cors from "cors";
import fetch from "node-fetch"; // Needed for Supabase fetch compatibility
import { createClient } from "@supabase/supabase-js";

const app = express();
app.use(cors());
app.use(express.json());

// --- Supabase client (service role only, never exposed in client)
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

app.post("/create-staff", async (req, res) => {
  try {
    const { admin_email, full_name, email, role } = req.body;

    // --- Verify admin session
    if (!admin_email) return res.status(401).json({ error: "Unauthorized" });

    const adminCheck = await supabase
      .from("profiles")
      .select("role")
      .eq("email", admin_email)
      .single();

    if (!adminCheck.data || adminCheck.data.role !== "admin") {
      return res.status(403).json({ error: "Forbidden: Not an admin" });
    }

    // --- Create staff in Auth (invite email)
    const { data: authData, error: authError } =
      await supabase.auth.admin.createUser({
        email,
        email_confirm: false, // triggers Supabase invite email
      });

    if (authError) return res.status(400).json({ error: authError.message });

    // --- Insert into profiles
    const { error: profileError } = await supabase
      .from("profiles")
      .insert({ id: authData.user.id, email, role, full_name });

    if (profileError) return res.status(400).json({ error: profileError.message });

    res.json({ success: true, user_id: authData.user.id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// --- Production listen
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
