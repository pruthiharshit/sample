// ============================================================================
// SINGLE CLOUDFLARE SERVER FILE: D1 Database + Private R2 Photos + Firebase Auth
// ============================================================================

const DEFAULT_FIREBASE_PROJECT_ID = 'anna-menu';

const SAFE_KEY_REGEX = /^[a-zA-Z0-9_-]{3,120}\.(webp|jpg|jpeg|png)$/;
const ALLOWED_SPICE = ['none', 'mild', 'medium', 'hot'];
const MAX_UPLOAD_BYTES = 2 * 1024 * 1024; // 2 MB limit

let dbInitialized = false;

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
      ...extraHeaders
    }
  });
}

// 1. Auto-Create D1 Tables & Seed Initial Anna South Indian Dosa Data on First Run
async function ensureDatabase(db) {
  if (dbInitialized) return;
  await db.batch([
    db.prepare(`
      CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        description TEXT DEFAULT '',
        display_order INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1,
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS menu_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT DEFAULT '',
        price_paise INTEGER NOT NULL DEFAULT 0,
        category_id INTEGER NOT NULL,
        image_key TEXT DEFAULT '',
        image_url TEXT DEFAULT '',
        is_vegetarian INTEGER NOT NULL DEFAULT 1,
        spice_level TEXT NOT NULL DEFAULT 'none',
        is_available INTEGER NOT NULL DEFAULT 1,
        is_featured INTEGER NOT NULL DEFAULT 0,
        display_order INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS restaurant_settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        restaurant_name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        address TEXT NOT NULL,
        phone TEXT NOT NULL,
        opening_hours TEXT NOT NULL DEFAULT '',
        services TEXT NOT NULL DEFAULT '[]',
        additional_settings TEXT NOT NULL DEFAULT '{}',
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        details TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
      )
    `),
    db.prepare(`
      INSERT OR IGNORE INTO restaurant_settings (
        id, restaurant_name, description, address, phone, opening_hours, services, additional_settings
      ) VALUES (
        1,
        'Anna South Indian Dosa',
        'Authentic South Indian delicacies freshly prepared in the heart of Sirsa since 2001.',
        'PNB St, near Geeta Bhawan, Rori Bazar, B Block, Subhash Chowk, Sirsa, Haryana 125055',
        '098135 01421',
        'Closes 11:00 PM',
        '["Dine-in","Drive-through","Delivery"]',
        '{"hindi_name":"अन्ना साउथ इंडियन डोसा","established":"Since 2001","category_label":"South Indian Restaurant"}'
      )
    `),
    db.prepare(`
      INSERT OR IGNORE INTO categories (name, description, display_order, is_active) VALUES
        ('Dosa', 'Crisp, golden fermented crepe specialties served with freshly prepared sambar and chutneys.', 1, 1),
        ('Idli & Vada', 'Steamed rice cakes and crisp lentil donuts served with traditional accompaniments.', 2, 1),
        ('Uttapam', 'Thick, savory South Indian griddle pancakes topped with fresh vegetables and spices.', 3, 1),
        ('South Indian Meals', 'Complete traditional platters and curated combinations.', 4, 1),
        ('Rice & Specials', 'Aromatic tempered rice dishes and house specialties.', 5, 1),
        ('Beverages', 'Refreshing drinks and traditional hot beverages.', 6, 1),
        ('Extras & Accompaniments', 'Additional sides, chutneys, sambar, and accompaniments.', 7, 1)
    `)
  ]);
  dbInitialized = true;
}

// 2. Cryptographically Verify Firebase ID Token (RS256 via Google Public JWKs)
function base64UrlToUint8Array(str) {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function verifyFirebaseToken(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  if (!authHeader.startsWith('Bearer ')) {
    return { ok: false, error: 'Missing Firebase login token.' };
  }

  const token = authHeader.slice(7).trim();
  const parts = token.split('.');
  if (parts.length !== 3) {
    return { ok: false, error: 'Malformed token.' };
  }

  try {
    const header = JSON.parse(new TextDecoder().decode(base64UrlToUint8Array(parts[0])));
    const payload = JSON.parse(new TextDecoder().decode(base64UrlToUint8Array(parts[1])));
    const signature = base64UrlToUint8Array(parts[2]);

    const projectId = (env.FIREBASE_PROJECT_ID || DEFAULT_FIREBASE_PROJECT_ID).trim();
    const nowSec = Math.floor(Date.now() / 1000);

    if (payload.exp <= nowSec) {
      return { ok: false, error: 'Session expired. Please sign in again.' };
    }
    if (
      projectId &&
      projectId !== 'REPLACE_WITH_YOUR_FIREBASE_PROJECT_ID' &&
      (payload.aud !== projectId || payload.iss !== `https://securetoken.google.com/${projectId}`)
    ) {
      return { ok: false, error: 'Token project ID mismatch.' };
    }

    // Fetch Google's public JWK set for Firebase Auth
    const jwksRes = await fetch(
      'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com'
    );
    const { keys } = await jwksRes.json();
    const jwk = (keys || []).find((k) => k.kid === header.kid);
    if (!jwk) {
      return { ok: false, error: 'Signing key not found.' };
    }

    const cryptoKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const signedData = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
    const isValid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, signature, signedData);
    if (!isValid) {
      return { ok: false, error: 'Invalid token signature.' };
    }

    if (env.ADMIN_EMAIL && payload.email?.toLowerCase() !== env.ADMIN_EMAIL.toLowerCase()) {
      return { ok: false, error: 'This email is not authorized as an administrator.' };
    }

    return { ok: true, email: payload.email || 'admin' };
  } catch {
    return { ok: false, error: 'Failed to verify Firebase authentication.' };
  }
}

async function logAudit(db, action, details) {
  try {
    await db
      .prepare(`INSERT INTO audit_logs (action, details) VALUES (?, ?)`)
      .bind(String(action).slice(0, 80), String(details).slice(0, 240))
      .run();
    await db
      .prepare(`DELETE FROM audit_logs WHERE id NOT IN (SELECT id FROM audit_logs ORDER BY id DESC LIMIT 80)`)
      .run();
  } catch {}
}

async function cleanupOrphanedR2Image(env, imageKey) {
  if (!imageKey || !SAFE_KEY_REGEX.test(imageKey)) return;
  try {
    const row = await env.DB.prepare(`SELECT COUNT(*) AS count FROM menu_items WHERE image_key = ?`)
      .bind(imageKey)
      .first();
    if (!row || row.count === 0) {
      await env.MEDIA_BUCKET.delete(imageKey);
    }
  } catch {}
}

function detectImageType(bytes) {
  if (bytes.length < 12) return null;
  if (
    bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
    bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50
  ) return { ext: 'webp', mime: 'image/webp' };
  if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return { ext: 'jpg', mime: 'image/jpeg' };
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return { ext: 'png', mime: 'image/png' };
  return null;
}

// ============================================================================
// MAIN CLOUDFLARE PAGES ENTRYPOINT
// ============================================================================
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();

  // --------------------------------------------------------------------------
  // A. PRIVATE R2 IMAGE DELIVERY (/media/dish-123.webp)
  // --------------------------------------------------------------------------
  if (path.startsWith('/media/')) {
    const key = path.slice('/media/'.length).trim();
    if (!SAFE_KEY_REGEX.test(key) || key.includes('..') || key.includes('/')) {
      return new Response('Invalid image key', { status: 400 });
    }

    try {
      const object = await env.MEDIA_BUCKET.get(key, { onlyIf: request.headers });
      if (!object) {
        return new Response('Image Not Found', { status: 404, headers: { 'Cache-Control': 'public, max-age=60' } });
      }

      const headers = new Headers();
      object.writeHttpMetadata(headers);
      headers.set('ETag', object.httpEtag);
      headers.set('Cache-Control', 'public, max-age=31536000, immutable');
      headers.set('X-Content-Type-Options', 'nosniff');

      if (!('body' in object) || !object.body) {
        return new Response(null, { status: 304, headers });
      }
      return new Response(object.body, { status: 200, headers });
    } catch {
      return new Response('Error reading image', { status: 500 });
    }
  }

  // --------------------------------------------------------------------------
  // B. BACKEND API ROUTES (/api/*)
  // --------------------------------------------------------------------------
  if (path.startsWith('/api/')) {
    await ensureDatabase(env.DB);

    // 1. Public Menu Endpoint (GET /api/menu)
    if (path === '/api/menu' && method === 'GET') {
      const [settingsRes, categoriesRes, itemsRes] = await env.DB.batch([
        env.DB.prepare(`SELECT * FROM restaurant_settings WHERE id = 1`),
        env.DB.prepare(`SELECT id, name, description, display_order FROM categories WHERE is_active = 1 ORDER BY display_order ASC, id ASC`),
        env.DB.prepare(`
          SELECT m.id, m.name, m.description, m.price_paise, m.category_id,
                 m.image_key, m.image_url, m.is_vegetarian, m.spice_level,
                 m.is_available, m.is_featured, m.display_order
          FROM menu_items m
          INNER JOIN categories c ON c.id = m.category_id
          WHERE c.is_active = 1
          ORDER BY m.display_order ASC, m.id ASC
        `)
      ]);

      const raw = settingsRes.results[0] || {};
      return json(
        {
          settings: {
            restaurant_name: raw.restaurant_name || 'Anna South Indian Dosa',
            description: raw.description || '',
            address: raw.address || '',
            phone: raw.phone || '098135 01421',
            opening_hours: raw.opening_hours || 'Closes 11:00 PM',
            services: JSON.parse(raw.services || '["Dine-in","Drive-through","Delivery"]'),
            additional_settings: JSON.parse(raw.additional_settings || '{}')
          },
          categories: categoriesRes.results || [],
          items: itemsRes.results || []
        },
        200,
        { 'Cache-Control': 'public, max-age=5, stale-while-revalidate=30' }
      );
    }

    // All routes below require a valid Firebase Admin Token
    const auth = await verifyFirebaseToken(request, env);
    if (!auth.ok) {
      return json({ error: auth.error }, 401, { 'Cache-Control': 'no-store' });
    }

    // 2. Admin Bootstrap Data (GET /api/admin-data)
    if (path === '/api/admin-data' && method === 'GET') {
      const [catsRes, itemsRes, setRes, logsRes] = await env.DB.batch([
        env.DB.prepare(`
          SELECT c.*, COUNT(m.id) AS item_count
          FROM categories c
          LEFT JOIN menu_items m ON m.category_id = c.id
          GROUP BY c.id
          ORDER BY c.display_order ASC, c.id ASC
        `),
        env.DB.prepare(`
          SELECT m.*, c.name AS category_name
          FROM menu_items m
          LEFT JOIN categories c ON c.id = m.category_id
          ORDER BY c.display_order ASC, m.display_order ASC, m.id DESC
        `),
        env.DB.prepare(`SELECT * FROM restaurant_settings WHERE id = 1`),
        env.DB.prepare(`SELECT id, action, details, created_at FROM audit_logs ORDER BY id DESC LIMIT 12`)
      ]);

      const raw = setRes.results[0] || {};
      return json({
        categories: catsRes.results || [],
        items: itemsRes.results || [],
        settings: {
          restaurant_name: raw.restaurant_name || '',
          description: raw.description || '',
          address: raw.address || '',
          phone: raw.phone || '',
          opening_hours: raw.opening_hours || '',
          services: JSON.parse(raw.services || '[]'),
          additional_settings: JSON.parse(raw.additional_settings || '{}')
        },
        recentLogs: logsRes.results || []
      }, 200, { 'Cache-Control': 'no-store' });
    }

    // 3. Upload Image to Private R2 (POST /api/upload)
    if (path === '/api/upload' && method === 'POST') {
      const formData = await request.formData();
      const file = formData.get('image');
      if (!file || typeof file.arrayBuffer !== 'function' || file.size === 0) {
        return json({ error: 'No image provided.' }, 400);
      }
      if (file.size > MAX_UPLOAD_BYTES) {
        return json({ error: 'Image exceeds 2 MB limit.' }, 413);
      }

      const buffer = await file.arrayBuffer();
      const detected = detectImageType(new Uint8Array(buffer));
      if (!detected) {
        return json({ error: 'Only valid WebP, JPEG, or PNG images are allowed.' }, 415);
      }

      const rand = Array.from(crypto.getRandomValues(new Uint8Array(6)))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
      const imageKey = `dish-${Date.now()}-${rand}.${detected.ext}`;

      await env.MEDIA_BUCKET.put(imageKey, buffer, {
        httpMetadata: {
          contentType: detected.mime,
          cacheControl: 'public, max-age=31536000, immutable'
        }
      });

      return json({
        ok: true,
        image_key: imageKey,
        image_url: `/media/${imageKey}`,
        size_bytes: buffer.byteLength
      }, 201);
    }

    // 4. Dishes CRUD (/api/items)
    if (path === '/api/items') {
      if (method === 'POST' || method === 'PUT') {
        const body = await request.json();
        const id = Number(body.id || 0);
        const name = String(body.name || '').trim();
        const description = String(body.description || '').trim();
        const pricePaise = Number(body.price_paise || 0);
        const categoryId = Number(body.category_id || 0);
        const imageKey = String(body.image_key || '').trim();
        const imageUrl = imageKey ? `/media/${imageKey}` : '';
        const isVegetarian = body.is_vegetarian === 0 ? 0 : 1;
        const spiceLevel = ALLOWED_SPICE.includes(body.spice_level) ? body.spice_level : 'none';
        const isAvailable = body.is_available === 0 ? 0 : 1;
        const isFeatured = body.is_featured ? 1 : 0;

        if (!name || pricePaise < 0 || !categoryId) {
          return json({ error: 'Dish name, valid price, and category are required.' }, 400);
        }

        if (method === 'POST') {
          await env.DB.prepare(`
            INSERT INTO menu_items (
              name, description, price_paise, category_id, image_key, image_url,
              is_vegetarian, spice_level, is_available, is_featured
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(name, description, pricePaise, categoryId, imageKey, imageUrl, isVegetarian, spiceLevel, isAvailable, isFeatured).run();
          await logAudit(env.DB, 'Dish Added', `Added "${name}" (₹${(pricePaise / 100).toFixed(0)})`);
          return json({ ok: true }, 201);
        } else {
          const old = await env.DB.prepare(`SELECT image_key FROM menu_items WHERE id = ?`).bind(id).first();
          await env.DB.prepare(`
            UPDATE menu_items
            SET name = ?, description = ?, price_paise = ?, category_id = ?,
                image_key = ?, image_url = ?, is_vegetarian = ?, spice_level = ?,
                is_available = ?, is_featured = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
            WHERE id = ?
          `).bind(name, description, pricePaise, categoryId, imageKey, imageUrl, isVegetarian, spiceLevel, isAvailable, isFeatured, id).run();

          if (old?.image_key && old.image_key !== imageKey) {
            await cleanupOrphanedR2Image(env, old.image_key);
          }
          await logAudit(env.DB, 'Dish Updated', `Updated "${name}"`);
          return json({ ok: true });
        }
      }

      if (method === 'PATCH') {
        const body = await request.json();
        const id = Number(body.id);
        const isAvailable = body.is_available ? 1 : 0;
        await env.DB.prepare(`UPDATE menu_items SET is_available = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ?`)
          .bind(isAvailable, id)
          .run();
        await logAudit(env.DB, 'Availability Toggled', `Dish #${id} set to ${isAvailable ? 'Available' : 'Unavailable'}`);
        return json({ ok: true });
      }

      if (method === 'DELETE') {
        const id = Number(url.searchParams.get('id'));
        const existing = await env.DB.prepare(`SELECT name, image_key FROM menu_items WHERE id = ?`).bind(id).first();
        await env.DB.prepare(`DELETE FROM menu_items WHERE id = ?`).bind(id).run();
        if (existing?.image_key) {
          await cleanupOrphanedR2Image(env, existing.image_key);
        }
        await logAudit(env.DB, 'Dish Deleted', `Deleted "${existing?.name || id}"`);
        return json({ ok: true });
      }
    }

    // 5. Categories CRUD (/api/categories)
    if (path === '/api/categories') {
      if (method === 'POST') {
        const body = await request.json();
        const name = String(body.name || '').trim();
        const description = String(body.description || '').trim();
        const isActive = body.is_active === 0 ? 0 : 1;
        const maxRow = await env.DB.prepare(`SELECT COALESCE(MAX(display_order), 0) AS m FROM categories`).first();
        await env.DB.prepare(`INSERT INTO categories (name, description, display_order, is_active) VALUES (?, ?, ?, ?)`)
          .bind(name, description, (maxRow?.m || 0) + 1, isActive)
          .run();
        await logAudit(env.DB, 'Category Added', `Created "${name}"`);
        return json({ ok: true }, 201);
      }

      if (method === 'PUT') {
        const body = await request.json();
        if (Array.isArray(body.orders)) {
          const stmts = body.orders.map((o) =>
            env.DB.prepare(`UPDATE categories SET display_order = ? WHERE id = ?`).bind(Number(o.display_order), Number(o.id))
          );
          if (stmts.length) await env.DB.batch(stmts);
          return json({ ok: true });
        }
        await env.DB.prepare(`
          UPDATE categories SET name = ?, description = ?, is_active = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
          WHERE id = ?
        `).bind(String(body.name).trim(), String(body.description || '').trim(), body.is_active ? 1 : 0, Number(body.id)).run();
        await logAudit(env.DB, 'Category Updated', `Updated "${body.name}"`);
        return json({ ok: true });
      }

      if (method === 'DELETE') {
        const id = Number(url.searchParams.get('id'));
        const used = await env.DB.prepare(`SELECT COUNT(*) AS count FROM menu_items WHERE category_id = ?`).bind(id).first();
        if (used && used.count > 0) {
          return json({ error: `Cannot delete category with ${used.count} dish(es). Move or delete those dishes first.` }, 400);
        }
        await env.DB.prepare(`DELETE FROM categories WHERE id = ?`).bind(id).run();
        await logAudit(env.DB, 'Category Deleted', `Deleted category #${id}`);
        return json({ ok: true });
      }
    }

    // 6. Restaurant Settings Update (PUT /api/settings)
    if (path === '/api/settings' && method === 'PUT') {
      const body = await request.json();
      await env.DB.prepare(`
        UPDATE restaurant_settings
        SET restaurant_name = ?, description = ?, address = ?, phone = ?,
            opening_hours = ?, services = ?, additional_settings = ?,
            updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
        WHERE id = 1
      `).bind(
        String(body.restaurant_name || 'Anna South Indian Dosa').trim(),
        String(body.description || '').trim(),
        String(body.address || '').trim(),
        String(body.phone || '').trim(),
        String(body.opening_hours || '').trim(),
        JSON.stringify(Array.isArray(body.services) ? body.services : []),
        JSON.stringify(body.additional_settings || {})
      ).run();
      await logAudit(env.DB, 'Settings Updated', 'Updated restaurant profile & hours');
      return json({ ok: true });
    }

    return json({ error: 'API route not found' }, 404);
  }

  // --------------------------------------------------------------------------
  // C. SERVE STATIC HTML FILES (/index.html, /admin.html)
  // --------------------------------------------------------------------------
  return context.next();
}