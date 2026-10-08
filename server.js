const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));

const PORT = process.env.PORT || 10000;
const url = process.env.SUPABASE_URL;
const key =
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  process.env.SUPABASE_SECRET_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET;

if (!url || !key || !ADMIN_PASSWORD || !JWT_SECRET) {
  console.error(
    "Missing required env vars: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_SECRET_KEY), ADMIN_PASSWORD, JWT_SECRET"
  );
  process.exit(1);
}

const supabase = createClient(url, key, {
  auth: { persistSession: false, autoRefreshToken: false }
});

const T = {
  accessKeys: process.env.ACCESS_KEYS_TABLE || "access_keys",
  users: process.env.USERS_TABLE || "Users",
  deposits: process.env.DEPOSITS_TABLE || "Deposit",
  withdrawals: process.env.WITHDRAWALS_TABLE || "Withdrawal",
  subPanels: process.env.SUBPANELS_TABLE || "sub_panels",
  settings: process.env.SETTINGS_TABLE || "app_settings"
};

function makeKey() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const part = () =>
    Array.from(
      { length: 4 },
      () => chars[crypto.randomInt(0, chars.length)]
    ).join("");
  return `${part()}-${part()}-${part()}`;
}

function signAdmin() {
  return jwt.sign({ role: "admin" }, JWT_SECRET, { expiresIn: "12h" });
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";

  try {
    const p = jwt.verify(token, JWT_SECRET);
    if (p.role !== "admin") throw new Error("forbidden");
    req.admin = p;
    next();
  } catch (_) {
    return res.status(401).json({
      ok: false,
      error: "Unauthorized"
    });
  }
}

function cleanStatus(v) {
  return String(v || "").toLowerCase();
}

app.get("/", (req, res) =>
  res.json({
    ok: true,
    name: "AI SUPER PREDICTOR Backend",
    status: "online"
  })
);

app.get("/api/health", (req, res) =>
  res.json({ ok: true, status: "online" })
);

app.post("/api/admin/login", (req, res) => {
  if (String(req.body?.password || "") !== ADMIN_PASSWORD) {
    return res.status(401).json({
      ok: false,
      error: "Invalid admin password"
    });
  }

  res.json({
    ok: true,
    token: signAdmin()
  });
});

/*
 * CREATE ACCESS KEY
 * New keys start active and unbound.
 */
app.post("/api/access-keys", auth, async (req, res) => {
  try {
    const days = Math.max(1, Number(req.body?.days || 1));
    const expires_at =
      req.body?.expires_at ||
      new Date(Date.now() + days * 86400000).toISOString();

    const row = {
      key: makeKey(),
      status: "active",
      expires_at,
      device_id: null,
      device_bound_at: null,
      last_used_at: null
    };

    const { data, error } = await supabase
      .from(T.accessKeys)
      .insert(row)
      .select()
      .single();

    if (error) {
      return res.status(400).json({
        ok: false,
        error: error.message
      });
    }

    res.json({
      ok: true,
      data
    });
  } catch (e) {
    res.status(500).json({
      ok: false,
      error: e.message
    });
  }
});

/*
 * LIST ACCESS KEYS
 */
app.get("/api/access-keys", auth, async (req, res) => {
  const { data, error } = await supabase
    .from(T.accessKeys)
    .select("*")
    .order("id", { ascending: false });

  if (error) {
    return res.status(400).json({
      ok: false,
      error: error.message
    });
  }

  res.json({
    ok: true,
    data
  });
});

/*
 * CHECK ACCESS KEY
 *
 * Client must send:
 * {
 *   "key": "XXXX-XXXX-XXXX",
 *   "device_id": "installation-uuid"
 * }
 *
 * First device binds the key.
 * A different device is rejected.
 */
app.post("/api/access-keys/check", async (req, res) => {
  try {
    const k = String(req.body?.key || "")
      .trim()
      .toUpperCase();

    const deviceId = String(req.body?.device_id || "").trim();

    if (!k) {
      return res.status(400).json({
        ok: false,
        valid: false,
        error: "Key required"
      });
    }

    if (!deviceId) {
      return res.status(400).json({
        ok: false,
        valid: false,
        error: "Device ID required"
      });
    }

    const { data, error } = await supabase
      .from(T.accessKeys)
      .select("*")
      .eq("key", k)
      .maybeSingle();

    if (error) {
      return res.status(400).json({
        ok: false,
        valid: false,
        error: error.message
      });
    }

    if (!data) {
      return res.json({
        ok: true,
        valid: false,
        reason: "not_found"
      });
    }

    if (cleanStatus(data.status) !== "active") {
      return res.json({
        ok: true,
        valid: false,
        reason: "disabled",
        data
      });
    }

    if (
      data.expires_at &&
      new Date(data.expires_at).getTime() < Date.now()
    ) {
      return res.json({
        ok: true,
        valid: false,
        reason: "expired",
        data
      });
    }

    /*
     * First successful device binds the key.
     * The database condition prevents a second device from
     * replacing an already-bound device.
     */
    if (!data.device_id) {
      const now = new Date().toISOString();

      const { data: bound, error: bindError } = await supabase
        .from(T.accessKeys)
        .update({
          device_id: deviceId,
          device_bound_at: now,
          last_used_at: now
        })
        .eq("id", data.id)
        .is("device_id", null)
        .select()
        .maybeSingle();

      if (bindError) {
        return res.status(400).json({
          ok: false,
          valid: false,
          error: bindError.message
        });
      }

      /*
       * Another request may have won the race and bound the key.
       * Re-read the row so the correct device can be checked.
       */
      if (!bound) {
        const { data: current, error: rereadError } = await supabase
          .from(T.accessKeys)
          .select("*")
          .eq("id", data.id)
          .maybeSingle();

        if (rereadError || !current) {
          return res.status(409).json({
            ok: false,
            valid: false,
            reason: "binding_conflict"
          });
        }

        if (current.device_id !== deviceId) {
          return res.json({
            ok: true,
            valid: false,
            reason: "device_mismatch"
          });
        }

        const { data: updated, error: updateError } = await supabase
          .from(T.accessKeys)
          .update({
            last_used_at: new Date().toISOString()
          })
          .eq("id", current.id)
          .select()
          .single();

        if (updateError) {
          return res.status(400).json({
            ok: false,
            valid: false,
            error: updateError.message
          });
        }

        return res.json({
          ok: true,
          valid: true,
          data: updated
        });
      }

      return res.json({
        ok: true,
        valid: true,
        data: bound
      });
    }

    /*
     * Already bound: only the same device may use the key.
     */
    if (data.device_id !== deviceId) {
      return res.json({
        ok: true,
        valid: false,
        reason: "device_mismatch"
      });
    }

    const { data: updated, error: updateError } = await supabase
      .from(T.accessKeys)
      .update({
        last_used_at: new Date().toISOString()
      })
      .eq("id", data.id)
      .select()
      .single();

    if (updateError) {
      return res.status(400).json({
        ok: false,
        valid: false,
        error: updateError.message
      });
    }

    return res.json({
      ok: true,
      valid: true,
      data: updated
    });
  } catch (e) {
    return res.status(500).json({
      ok: false,
      valid: false,
      error: e.message
    });
  }
});

/*
 * UPDATE KEY STATUS
 *
 * Existing admin panel can continue using:
 * PATCH /api/access-keys/:id
 * { "status": "active" }
 * or
 * { "status": "blocked" }
 *
 * Reset device:
 * PATCH /api/access-keys/:id
 * { "reset_device": true }
 *
 * Both can be sent together.
 */
app.patch("/api/access-keys/:id", auth, async (req, res) => {
  const update = {};

  if (typeof req.body?.status === "string") {
    const status = cleanStatus(req.body.status);

    if (!["active", "blocked", "disabled"].includes(status)) {
      return res.status(400).json({
        ok: false,
        error: "Invalid status"
      });
    }

    update.status = status;
  }

  if (req.body?.reset_device === true) {
    update.device_id = null;
    update.device_bound_at = null;
    update.last_used_at = null;
  }

  if (Object.keys(update).length === 0) {
    return res.status(400).json({
      ok: false,
      error: "Nothing to update"
    });
  }

  const { data, error } = await supabase
    .from(T.accessKeys)
    .update(update)
    .eq("id", req.params.id)
    .select()
    .single();

  if (error) {
    return res.status(400).json({
      ok: false,
      error: error.message
    });
  }

  res.json({
    ok: true,
    data
  });
});

/*
 * USERS
 */
app.get("/api/users", auth, async (req, res) => {
  const { data, error } = await supabase
    .from(T.users)
    .select("*")
    .order("uid", { ascending: true });

  if (error) {
    return res.status(400).json({
      ok: false,
      error: error.message
    });
  }

  res.json({
    ok: true,
    data
  });
});

app.patch("/api/users/:uid/lock", auth, async (req, res) => {
  const locked = Boolean(req.body?.locked);

  const update = {
    status: locked ? "locked" : "active",
    lock_reason: locked ? req.body?.reason || null : null
  };

  const { data, error } = await supabase
    .from(T.users)
    .update(update)
    .eq("uid", req.params.uid)
    .select()
    .single();

  if (error) {
    return res.status(400).json({
      ok: false,
      error: error.message
    });
  }

  res.json({
    ok: true,
    data
  });
});

/*
 * DEPOSITS
 */
app.get("/api/deposits", auth, async (req, res) => {
  const { data, error } = await supabase
    .from(T.deposits)
    .select("*")
    .order("id", { ascending: false });

  if (error) {
    return res.status(400).json({
      ok: false,
      error: error.message
    });
  }

  res.json({
    ok: true,
    data
  });
});

app.patch("/api/deposits/:id", auth, async (req, res) => {
  const status = cleanStatus(req.body?.status);

  if (!["approved", "rejected", "pending"].includes(status)) {
    return res.status(400).json({
      ok: false,
      error: "Invalid status"
    });
  }

  const { data, error } = await supabase
    .from(T.deposits)
    .update({ status })
    .eq("id", req.params.id)
    .select()
    .single();

  if (error) {
    return res.status(400).json({
      ok: false,
      error: error.message
    });
  }

  res.json({
    ok: true,
    data
  });
});

/*
 * WITHDRAWALS
 */
app.get("/api/withdrawals", auth, async (req, res) => {
  const { data, error } = await supabase
    .from(T.withdrawals)
    .select("*")
    .order("id", { ascending: false });

  if (error) {
    return res.status(400).json({
      ok: false,
      error: error.message
    });
  }

  res.json({
    ok: true,
    data
  });
});

app.patch("/api/withdrawals/:id", auth, async (req, res) => {
  const status = cleanStatus(req.body?.status);

  if (!["approved", "rejected", "pending"].includes(status)) {
    return res.status(400).json({
      ok: false,
      error: "Invalid status"
    });
  }

  const { data, error } = await supabase
    .from(T.withdrawals)
    .update({ status })
    .eq("id", req.params.id)
    .select()
    .single();

  if (error) {
    return res.status(400).json({
      ok: false,
      error: error.message
    });
  }

  res.json({
    ok: true,
    data
  });
});

/*
 * SUB-PANELS
 */
app.get("/api/sub-panels", auth, async (req, res) => {
  const { data, error } = await supabase
    .from(T.subPanels)
    .select("id,name,username,active,permissions,created_at")
    .order("id", { ascending: false });

  if (error) {
    return res.status(400).json({
      ok: false,
      error: error.message
    });
  }

  res.json({
    ok: true,
    data
  });
});

app.post("/api/sub-panels", auth, async (req, res) => {
  try {
    const name = String(req.body?.name || "").trim();
    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");

    if (!name || !username || !password) {
      return res.status(400).json({
        ok: false,
        error: "Name, username and password required"
      });
    }

    const password_hash = await bcrypt.hash(password, 12);
    const permissions = req.body?.permissions || {};

    const { data, error } = await supabase
      .from(T.subPanels)
      .insert({
        name,
        username,
        password_hash,
        active: true,
        permissions
      })
      .select("id,name,username,active,permissions,created_at")
      .single();

    if (error) {
      return res.status(400).json({
        ok: false,
        error: error.message
      });
    }

    res.json({
      ok: true,
      data
    });
  } catch (e) {
    res.status(500).json({
      ok: false,
      error: e.message
    });
  }
});

app.patch("/api/sub-panels/:id", auth, async (req, res) => {
  const update = {};

  if (typeof req.body?.active === "boolean") {
    update.active = req.body.active;
  }

  if (req.body?.permissions) {
    update.permissions = req.body.permissions;
  }

  const { data, error } = await supabase
    .from(T.subPanels)
    .update(update)
    .eq("id", req.params.id)
    .select("id,name,username,active,permissions,created_at")
    .single();

  if (error) {
    return res.status(400).json({
      ok: false,
      error: error.message
    });
  }

  res.json({
    ok: true,
    data
  });
});

app.delete("/api/sub-panels/:id", auth, async (req, res) => {
  const { error } = await supabase
    .from(T.subPanels)
    .delete()
    .eq("id", req.params.id);

  if (error) {
    return res.status(400).json({
      ok: false,
      error: error.message
    });
  }

  res.json({
    ok: true
  });
});

app.post("/api/sub-panels/login", async (req, res) => {
  try {
    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");

    const { data, error } = await supabase
      .from(T.subPanels)
      .select(
        "id,name,username,password_hash,active,permissions"
      )
      .eq("username", username)
      .maybeSingle();

    if (error) {
      return res.status(400).json({
        ok: false,
        error: error.message
      });
    }

    if (
      !data ||
      !data.active ||
      !(await bcrypt.compare(password, data.password_hash))
    ) {
      return res.status(401).json({
        ok: false,
        error: "Invalid username/password"
      });
    }

    const token = jwt.sign(
      {
        role: "subpanel",
        subpanel_id: data.id,
        username: data.username,
        permissions: data.permissions || {}
      },
      JWT_SECRET,
      { expiresIn: "12h" }
    );

    res.json({
      ok: true,
      token,
      data: {
        id: data.id,
        name: data.name,
        username: data.username,
        permissions: data.permissions || {}
      }
    });
  } catch (e) {
    res.status(500).json({
      ok: false,
      error: e.message
    });
  }
});

app.listen(PORT, () =>
  console.log(`Backend running on port ${PORT}`)
);
