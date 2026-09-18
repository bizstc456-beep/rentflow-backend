// ============================================
// FILE: server.js - RENTFLOW BACKEND
// ============================================

const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { createClient } = require('@supabase/supabase-js');
const Stripe = require('stripe');
const twilio = require('twilio');
const Anthropic = require('@anthropic-ai/sdk');
const multer = require('multer');

// Load .env only in development, not in production (Railway)
if (process.env.NODE_ENV !== 'production') {
  dotenv.config();
}

// ============================================
// INITIALIZE ALL SERVICES
// ============================================

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// Supabase (Database)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Stripe (Payments)
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// Twilio (SMS)
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

// Claude (AI)
const anthropic = new Anthropic({
  apiKey: process.env.CLAUDE_API_KEY
});

// File uploads (documents) -- held in memory, then streamed to Supabase
// Storage. 15MB cap covers scanned leases/IDs comfortably.
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 15 * 1024 * 1024 } });

// ============================================
// AUTH HELPERS
// ============================================

// Landlords who are allowed to see the Admin Dashboard.
// Configure via ADMIN_EMAILS="a@x.com,b@y.com" in Railway; falls back to the founder account.
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || 'bizstc456@gmail.com')
  .split(',')
  .map(e => e.trim().toLowerCase())
  .filter(Boolean);

// Verifies the Supabase access token sent as "Authorization: Bearer <token>"
// and returns the authenticated user, or null if missing/invalid.
async function getAuthenticatedUser(req) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return null;

  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data?.user) return null;
  return data.user;
}

// Express middleware: requires a valid session, attaches req.user.
async function requireAuth(req, res, next) {
  const user = await getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Missing or invalid session' });
  }
  req.user = user;
  next();
}

// Express middleware: requires a valid session AND an admin email.
async function requireAdmin(req, res, next) {
  const user = await getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Missing or invalid session' });
  }
  if (!ADMIN_EMAILS.includes((user.email || '').toLowerCase())) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  req.user = user;
  next();
}

// Express middleware: requires a valid session that is linked to a tenant
// record (tenants.auth_user_id), for the tenant self-service portal.
// Attaches the tenant row as req.tenant.
async function requireTenantAuth(req, res, next) {
  const user = await getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Missing or invalid session' });
  }

  const { data: tenant, error } = await supabase
    .from('tenants')
    .select('*')
    .eq('auth_user_id', user.id)
    .single();

  if (error || !tenant) {
    return res.status(403).json({ error: 'No tenant portal account is linked to this login' });
  }

  req.user = user;
  req.tenant = tenant;
  next();
}

// ============================================
// AUTHENTICATION ROUTES
// ============================================

// Register new landlord
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, phone } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const { data: authData, error: authError } = await supabase.auth.signUp({
      email,
      password
    });

    if (authError) {
      return res.status(400).json({ error: authError.message });
    }

    const { data: customer, error: dbError } = await supabase
      .from('customers')
      .insert([
        {
          user_id: authData.user.id,
          email,
          name,
          phone,
          trial_ends_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
          status: 'active'
        }
      ])
      .select();

    if (dbError) {
      return res.status(400).json({ error: dbError.message });
    }

    res.json({
      success: true,
      customer: customer[0],
      user: authData.user
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({
      success: true,
      user: data.user,
      session: data.session
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// PROPERTY MANAGEMENT ROUTES
// ============================================

// Create property
app.post('/api/properties', requireAuth, async (req, res) => {
  try {
    const { address, city, province, postal_code, property_type, bedrooms, bathrooms, notes } = req.body;

    if (!address || !city) {
      return res.status(400).json({ error: 'Address and city are required' });
    }

    const { data, error } = await supabase
      .from('properties')
      .insert([
        {
          user_id: req.user.id,
          address,
          city,
          province,
          postal_code,
          property_type,
          bedrooms,
          bathrooms,
          notes,
          created_at: new Date()
        }
      ])
      .select();

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, property: data[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all properties for a landlord
app.get('/api/properties/:user_id', requireAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (req.user.id !== user_id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's properties" });
    }

    const { data, error } = await supabase
      .from('properties')
      .select('*')
      .eq('user_id', user_id)
      .order('created_at', { ascending: true });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, properties: data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update a property you own. user_id is never accepted from the client --
// ownership can't be transferred through this route.
app.put('/api/properties/:property_id', requireAuth, async (req, res) => {
  try {
    const { property_id } = req.params;

    const { data: existing, error: fetchError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', property_id)
      .single();
    if (fetchError || !existing) {
      return res.status(404).json({ error: 'Property not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (existing.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this property' });
    }

    const { address, city, province, postal_code, property_type, bedrooms, bathrooms, notes } = req.body;
    const updates = { address, city, province, postal_code, property_type, bedrooms, bathrooms, notes };

    const { data, error } = await supabase
      .from('properties')
      .update(updates)
      .eq('id', property_id)
      .select();

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, property: data[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete a property (and everything under it) you manage. Removes its
// tenants' payments and documents, the tenants themselves, the property's
// own documents, then the property. There's no undo -- the frontend confirms first.
app.delete('/api/properties/:property_id', requireAuth, async (req, res) => {
  try {
    const { property_id } = req.params;

    const { data: existing, error: fetchError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', property_id)
      .single();
    if (fetchError || !existing) {
      return res.status(404).json({ error: 'Property not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (existing.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this property' });
    }

    const { data: tenants } = await supabase
      .from('tenants')
      .select('id')
      .eq('property_id', property_id);
    const tenantIds = (tenants || []).map(t => t.id);

    const docFilter = tenantIds.length
      ? `property_id.eq.${property_id},tenant_id.in.(${tenantIds.join(',')})`
      : `property_id.eq.${property_id}`;
    const { data: docs } = await supabase
      .from('documents')
      .select('storage_path')
      .or(docFilter);
    if (docs && docs.length) {
      await supabase.storage.from(DOCUMENTS_BUCKET).remove(docs.map(d => d.storage_path));
      await supabase.from('documents').delete().or(docFilter);
    }

    if (tenantIds.length) {
      await supabase.from('payments').delete().in('tenant_id', tenantIds);
    }

    await supabase.from('tenants').delete().eq('property_id', property_id);

    const { error } = await supabase.from('properties').delete().eq('id', property_id);
    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// TENANT MANAGEMENT ROUTES
// ============================================

// Add a tenant (a unit + its lease) to a property you own
app.post('/api/tenants', requireAuth, async (req, res) => {
  try {
    const { property_id, name, email, phone, unit_label, rent_amount, lease_start_date, lease_end_date } = req.body;

    if (!property_id || !name || !phone) {
      return res.status(400).json({ error: 'property_id, name, and phone are required' });
    }

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this property' });
    }

    const { data, error } = await supabase
      .from('tenants')
      .insert([
        {
          property_id,
          name,
          email,
          phone,
          unit_label,
          rent_amount,
          lease_start_date,
          lease_end_date,
          created_at: new Date()
        }
      ])
      .select();

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, tenant: data[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update a tenant/lease you manage
app.put('/api/tenants/:tenant_id', requireAuth, async (req, res) => {
  try {
    const { tenant_id } = req.params;

    const { data: tenant, error: tenantError } = await supabase
      .from('tenants')
      .select('property_id')
      .eq('id', tenant_id)
      .single();
    if (tenantError || !tenant) {
      return res.status(404).json({ error: 'Tenant not found' });
    }

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', tenant.property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found for this tenant' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this tenant' });
    }

    const { name, email, phone, unit_label, rent_amount, lease_start_date, lease_end_date } = req.body;
    const updates = { name, email, phone, unit_label, rent_amount, lease_start_date, lease_end_date };

    const { data, error } = await supabase
      .from('tenants')
      .update(updates)
      .eq('id', tenant_id)
      .select();

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, tenant: data[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete a tenant (lease ended / unit vacated) you manage. Cascades to that
// tenant's payments and documents so nothing orphaned is left behind.
app.delete('/api/tenants/:tenant_id', requireAuth, async (req, res) => {
  try {
    const { tenant_id } = req.params;

    const { data: tenant, error: tenantError } = await supabase
      .from('tenants')
      .select('property_id')
      .eq('id', tenant_id)
      .single();
    if (tenantError || !tenant) {
      return res.status(404).json({ error: 'Tenant not found' });
    }

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', tenant.property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found for this tenant' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this tenant' });
    }

    const { data: docs } = await supabase
      .from('documents')
      .select('storage_path')
      .eq('tenant_id', tenant_id);
    if (docs && docs.length) {
      await supabase.storage.from(DOCUMENTS_BUCKET).remove(docs.map(d => d.storage_path));
      await supabase.from('documents').delete().eq('tenant_id', tenant_id);
    }

    await supabase.from('payments').delete().eq('tenant_id', tenant_id);

    const { error } = await supabase.from('tenants').delete().eq('id', tenant_id);
    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get tenants for a single property you own
app.get('/api/tenants/:property_id', requireAuth, async (req, res) => {
  try {
    const { property_id } = req.params;

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's tenants" });
    }

    const { data, error } = await supabase
      .from('tenants')
      .select('*')
      .eq('property_id', property_id);

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, tenants: data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// PAYMENT TRACKING ROUTES
// ============================================

// Mark a payment as paid for a tenant you manage
app.post('/api/payments/mark-paid', requireAuth, async (req, res) => {
  try {
    const { tenant_id, amount, payment_date, payment_method } = req.body;

    if (!tenant_id || !amount) {
      return res.status(400).json({ error: 'tenant_id and amount are required' });
    }

    const { data: tenantData, error: tenantError } = await supabase
      .from('tenants')
      .select('name, phone, property_id')
      .eq('id', tenant_id)
      .single();
    if (tenantError || !tenantData) {
      return res.status(404).json({ error: 'Tenant not found' });
    }

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', tenantData.property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found for this tenant' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this tenant' });
    }

    const { data: paymentData, error: paymentError } = await supabase
      .from('payments')
      .insert([
        {
          tenant_id,
          amount,
          payment_date: payment_date || new Date(),
          payment_method,
          status: 'paid',
          created_at: new Date()
        }
      ])
      .select();

    if (paymentError) {
      return res.status(400).json({ error: paymentError.message });
    }

    // A payment is already recorded at this point -- a failed confirmation
    // text is logged but shouldn't make the request look like it failed.
    let message = null;
    try {
      message = await generatePaymentConfirmationMessage(tenantData.name, amount);
      await sendSMS(tenantData.phone, message, property.user_id);
    } catch (smsError) {
      console.error('Payment confirmation SMS failed:', smsError);
    }

    const receipt = generateReceipt(
      tenantData.name,
      amount,
      payment_date,
      payment_method
    );

    res.json({
      success: true,
      payment: paymentData[0],
      message,
      receipt
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get payment history for a tenant you manage
app.get('/api/payments/:tenant_id', requireAuth, async (req, res) => {
  try {
    const { tenant_id } = req.params;

    const { data: tenantData, error: tenantError } = await supabase
      .from('tenants')
      .select('property_id')
      .eq('id', tenant_id)
      .single();
    if (tenantError || !tenantData) {
      return res.status(404).json({ error: 'Tenant not found' });
    }

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', tenantData.property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found for this tenant' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's payments" });
    }

    const { data, error } = await supabase
      .from('payments')
      .select('*')
      .eq('tenant_id', tenant_id)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, payments: data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all payments for a property you own
app.get('/api/payments/property/:property_id', requireAuth, async (req, res) => {
  try {
    const { property_id } = req.params;

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's payments" });
    }

    const { data: tenants, error: tenantError } = await supabase
      .from('tenants')
      .select('id')
      .eq('property_id', property_id);

    if (tenantError) {
      return res.status(400).json({ error: tenantError.message });
    }

    const tenantIds = tenants.map(t => t.id);
    if (tenantIds.length === 0) {
      return res.json({ success: true, payments: [] });
    }

    const { data, error } = await supabase
      .from('payments')
      .select('*, tenants(name, phone)')
      .in('tenant_id', tenantIds)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, payments: data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// EXPENSE TRACKING ROUTES
// ============================================
// Expenses are property-level (repairs, insurance, taxes, mortgage,
// utilities, management, other) and store user_id directly, unlike
// tenants/payments -- so listing/ownership checks don't need a join back
// through properties.

const EXPENSE_CATEGORIES = ['repairs', 'insurance', 'taxes', 'mortgage', 'utilities', 'management', 'other'];

// Add an expense for a property you own
app.post('/api/expenses', requireAuth, async (req, res) => {
  try {
    const { property_id, category, amount, expense_date, notes } = req.body;

    if (!property_id || !amount || !expense_date) {
      return res.status(400).json({ error: 'property_id, amount, and expense_date are required' });
    }

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this property' });
    }

    const safeCategory = EXPENSE_CATEGORIES.includes(category) ? category : 'other';

    const { data, error } = await supabase
      .from('expenses')
      .insert([{
        user_id: property.user_id,
        property_id,
        category: safeCategory,
        amount,
        expense_date,
        notes: notes || null,
        created_at: new Date(),
      }])
      .select();

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, expense: data[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update an expense you own
app.put('/api/expenses/:expense_id', requireAuth, async (req, res) => {
  try {
    const { expense_id } = req.params;

    const { data: existing, error: fetchError } = await supabase
      .from('expenses')
      .select('user_id')
      .eq('id', expense_id)
      .single();
    if (fetchError || !existing) {
      return res.status(404).json({ error: 'Expense not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (existing.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this expense' });
    }

    const { category, amount, expense_date, notes } = req.body;
    const updates = {
      category: EXPENSE_CATEGORIES.includes(category) ? category : 'other',
      amount,
      expense_date,
      notes: notes || null,
    };

    const { data, error } = await supabase
      .from('expenses')
      .update(updates)
      .eq('id', expense_id)
      .select();

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, expense: data[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete an expense you own
app.delete('/api/expenses/:expense_id', requireAuth, async (req, res) => {
  try {
    const { expense_id } = req.params;

    const { data: existing, error: fetchError } = await supabase
      .from('expenses')
      .select('user_id')
      .eq('id', expense_id)
      .single();
    if (fetchError || !existing) {
      return res.status(404).json({ error: 'Expense not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (existing.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this expense' });
    }

    const { error } = await supabase.from('expenses').delete().eq('id', expense_id);
    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// All expenses for a landlord, across every property (used by the Reports page)
app.get('/api/expenses/landlord/:user_id', requireAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (req.user.id !== user_id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's expenses" });
    }

    const { data, error } = await supabase
      .from('expenses')
      .select('*')
      .eq('user_id', user_id)
      .order('expense_date', { ascending: false });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, expenses: data || [] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Expenses for a single property you own
app.get('/api/expenses/property/:property_id', requireAuth, async (req, res) => {
  try {
    const { property_id } = req.params;

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's expenses" });
    }

    const { data, error } = await supabase
      .from('expenses')
      .select('*')
      .eq('property_id', property_id)
      .order('expense_date', { ascending: false });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, expenses: data || [] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// REPORTING ROUTES
// ============================================
// Income/expense report for a date range -- real money in and real money
// out only (paid payments, recorded expenses). Deliberately doesn't try to
// project "expected" rent over an arbitrary range (that gets fuzzy fast once
// tenants move in/out mid-range); the Dashboard's current-month numbers
// already cover "expected vs collected" for the present month.
app.get('/api/reports/:user_id', requireAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (req.user.id !== user_id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's reports" });
    }

    const today = new Date();
    const defaultStart = new Date(today.getFullYear(), 0, 1).toISOString().slice(0, 10);
    const defaultEnd = today.toISOString().slice(0, 10);
    const start = req.query.start || defaultStart;
    const end = req.query.end || defaultEnd;

    const { data: properties, error: propsError } = await supabase
      .from('properties')
      .select('id, address')
      .eq('user_id', user_id);
    if (propsError) return res.status(400).json({ error: propsError.message });

    const propertyIds = properties.map(p => p.id);

    const { data: tenants } = await supabase
      .from('tenants')
      .select('id, property_id')
      .in('property_id', propertyIds.length ? propertyIds : ['00000000-0000-0000-0000-000000000000']);

    const tenantToProperty = {};
    (tenants || []).forEach(t => { tenantToProperty[t.id] = t.property_id; });
    const tenantIds = (tenants || []).map(t => t.id);

    let payments = [];
    if (tenantIds.length) {
      const { data } = await supabase
        .from('payments')
        .select('*')
        .in('tenant_id', tenantIds)
        .eq('status', 'paid')
        .gte('payment_date', start)
        .lte('payment_date', end);
      payments = data || [];
    }

    const { data: expensesData } = await supabase
      .from('expenses')
      .select('*')
      .eq('user_id', user_id)
      .gte('expense_date', start)
      .lte('expense_date', end);
    const expenses = expensesData || [];

    const incomeByProperty = {};
    payments.forEach(p => {
      const propertyId = tenantToProperty[p.tenant_id];
      if (!propertyId) return;
      incomeByProperty[propertyId] = (incomeByProperty[propertyId] || 0) + (p.amount || 0);
    });

    const expensesByProperty = {};
    const expensesByCategory = {};
    expenses.forEach(e => {
      expensesByProperty[e.property_id] = (expensesByProperty[e.property_id] || 0) + (e.amount || 0);
      expensesByCategory[e.category] = (expensesByCategory[e.category] || 0) + (e.amount || 0);
    });

    const propertyReports = properties.map(p => {
      const income = incomeByProperty[p.id] || 0;
      const propertyExpenses = expensesByProperty[p.id] || 0;
      return {
        id: p.id,
        address: p.address,
        income,
        expenses: propertyExpenses,
        net: income - propertyExpenses,
      };
    });

    const totalIncome = payments.reduce((sum, p) => sum + (p.amount || 0), 0);
    const totalExpenses = expenses.reduce((sum, e) => sum + (e.amount || 0), 0);

    res.json({
      success: true,
      range: { start, end },
      summary: {
        income: totalIncome,
        expenses: totalExpenses,
        net: totalIncome - totalExpenses,
      },
      expenses_by_category: Object.entries(expensesByCategory).map(([category, amount]) => ({ category, amount })),
      properties: propertyReports,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// DOCUMENT MANAGEMENT ROUTES
// ============================================
// Files live in the private "documents" Supabase Storage bucket, one row per
// file in the "documents" table. A document is attached to a tenant (lease,
// ID copy, ...) or directly to a property (insurance policy, deed, ...),
// never both at once.

const DOCUMENTS_BUCKET = 'documents';

// Returns the landlord user_id that owns this tenant/property, or null.
async function resolveDocumentOwner(tenant_id, property_id) {
  if (tenant_id) {
    const { data: tenant } = await supabase
      .from('tenants')
      .select('property_id')
      .eq('id', tenant_id)
      .single();
    if (!tenant) return null;
    const { data: property } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', tenant.property_id)
      .single();
    return property?.user_id || null;
  }
  if (property_id) {
    const { data: property } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', property_id)
      .single();
    return property?.user_id || null;
  }
  return null;
}

// Upload a document for a tenant or a property you manage.
// multipart/form-data fields: file, and either tenant_id or property_id, plus optional category.
app.post('/api/documents/upload', requireAuth, upload.single('file'), async (req, res) => {
  try {
    const { tenant_id, property_id, category } = req.body;
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    if (!tenant_id && !property_id) {
      return res.status(400).json({ error: 'tenant_id or property_id is required' });
    }

    const ownerId = await resolveDocumentOwner(tenant_id, property_id);
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (!ownerId || (ownerId !== req.user.id && !isAdmin)) {
      return res.status(403).json({ error: 'You do not manage this tenant or property' });
    }

    const safeName = req.file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_');
    const storagePath = `${req.user.id}/${tenant_id || property_id}/${Date.now()}-${safeName}`;

    const { error: uploadError } = await supabase.storage
      .from(DOCUMENTS_BUCKET)
      .upload(storagePath, req.file.buffer, { contentType: req.file.mimetype });
    if (uploadError) {
      return res.status(400).json({ error: uploadError.message });
    }

    const { data, error } = await supabase
      .from('documents')
      .insert([{
        user_id: req.user.id,
        tenant_id: tenant_id || null,
        property_id: property_id || null,
        file_name: req.file.originalname,
        storage_path: storagePath,
        mime_type: req.file.mimetype,
        file_size: req.file.size,
        category: category || 'other',
        created_at: new Date(),
      }])
      .select();

    if (error) {
      // Insert failed -- remove the file we just uploaded so storage never
      // ends up with an orphaned object that has no matching row.
      await supabase.storage.from(DOCUMENTS_BUCKET).remove([storagePath]);
      return res.status(400).json({ error: error.message });
    }

    const { data: signed } = await supabase.storage
      .from(DOCUMENTS_BUCKET)
      .createSignedUrl(storagePath, 3600);

    res.json({ success: true, document: { ...data[0], url: signed?.signedUrl || null } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// List documents for a tenant you manage
app.get('/api/documents/tenant/:tenant_id', requireAuth, async (req, res) => {
  try {
    const { tenant_id } = req.params;
    const ownerId = await resolveDocumentOwner(tenant_id, null);
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (!ownerId || (ownerId !== req.user.id && !isAdmin)) {
      return res.status(403).json({ error: "Cannot view another user's documents" });
    }

    const { data, error } = await supabase
      .from('documents')
      .select('*')
      .eq('tenant_id', tenant_id)
      .order('created_at', { ascending: false });
    if (error) return res.status(400).json({ error: error.message });

    const withUrls = await Promise.all((data || []).map(async (doc) => {
      const { data: signed } = await supabase.storage
        .from(DOCUMENTS_BUCKET)
        .createSignedUrl(doc.storage_path, 3600);
      return { ...doc, url: signed?.signedUrl || null };
    }));

    res.json({ success: true, documents: withUrls });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// List documents attached directly to a property you manage (building-level
// docs only -- a tenant's own documents come from the route above).
app.get('/api/documents/property/:property_id', requireAuth, async (req, res) => {
  try {
    const { property_id } = req.params;
    const ownerId = await resolveDocumentOwner(null, property_id);
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (!ownerId || (ownerId !== req.user.id && !isAdmin)) {
      return res.status(403).json({ error: "Cannot view another user's documents" });
    }

    const { data, error } = await supabase
      .from('documents')
      .select('*')
      .eq('property_id', property_id)
      .order('created_at', { ascending: false });
    if (error) return res.status(400).json({ error: error.message });

    const withUrls = await Promise.all((data || []).map(async (doc) => {
      const { data: signed } = await supabase.storage
        .from(DOCUMENTS_BUCKET)
        .createSignedUrl(doc.storage_path, 3600);
      return { ...doc, url: signed?.signedUrl || null };
    }));

    res.json({ success: true, documents: withUrls });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete a document you own
app.delete('/api/documents/:document_id', requireAuth, async (req, res) => {
  try {
    const { document_id } = req.params;

    const { data: doc, error: fetchError } = await supabase
      .from('documents')
      .select('*')
      .eq('id', document_id)
      .single();
    if (fetchError || !doc) {
      return res.status(404).json({ error: 'Document not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (doc.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this document' });
    }

    await supabase.storage.from(DOCUMENTS_BUCKET).remove([doc.storage_path]);
    const { error } = await supabase.from('documents').delete().eq('id', document_id);
    if (error) return res.status(400).json({ error: error.message });

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// TENANT PORTAL & MAINTENANCE ROUTES
// ============================================
// Tenants get invite-only accounts (landlord triggers a Supabase invite
// email; the tenant sets a password and logs in with email+password from
// then on -- same recovery-link pattern as the landlord forgot-password
// flow). A tenant's Supabase auth user is linked back to their tenants row
// via tenants.auth_user_id. v1 scope is view-only lease/payment info plus
// maintenance request submission -- no in-portal payments yet.

const MAINTENANCE_STATUSES = ['open', 'in_progress', 'resolved'];

// Invite a tenant you manage to create their portal login
app.post('/api/tenants/:tenant_id/invite', requireAuth, async (req, res) => {
  try {
    const { tenant_id } = req.params;

    const { data: tenant, error: tenantError } = await supabase
      .from('tenants')
      .select('*')
      .eq('id', tenant_id)
      .single();
    if (tenantError || !tenant) {
      return res.status(404).json({ error: 'Tenant not found' });
    }

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', tenant.property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found for this tenant' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this tenant' });
    }

    if (!tenant.email) {
      return res.status(400).json({ error: 'Add an email address for this tenant before inviting them' });
    }
    if (tenant.auth_user_id) {
      return res.status(400).json({ error: 'This tenant already has a portal account' });
    }

    const frontendUrl = process.env.FRONTEND_URL || 'https://rentflow-frontend-phi.vercel.app';

    const { data: inviteData, error: inviteError } = await supabase.auth.admin.inviteUserByEmail(
      tenant.email,
      { redirectTo: `${frontendUrl}/tenant/set-password` }
    );

    if (inviteError) {
      return res.status(400).json({ error: inviteError.message });
    }

    const { error: updateError } = await supabase
      .from('tenants')
      .update({ auth_user_id: inviteData.user.id, invited_at: new Date() })
      .eq('id', tenant_id);

    if (updateError) {
      return res.status(400).json({ error: updateError.message });
    }

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Tenant portal: my lease/rental info
app.get('/api/tenant-portal/me', requireTenantAuth, async (req, res) => {
  try {
    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('address')
      .eq('id', req.tenant.property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found' });
    }

    res.json({ success: true, tenant: req.tenant, property });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Tenant portal: my payment history + current balance
app.get('/api/tenant-portal/payments', requireTenantAuth, async (req, res) => {
  try {
    const { data: payments, error } = await supabase
      .from('payments')
      .select('*')
      .eq('tenant_id', req.tenant.id)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    // Same current-month balance math used on the landlord's tenant list,
    // so "amount due" here always matches what the landlord sees.
    const startOfMonth = new Date(new Date().getFullYear(), new Date().getMonth(), 1);
    const collectedThisMonth = (payments || [])
      .filter(p => p.status === 'paid' && new Date(p.created_at) >= startOfMonth)
      .reduce((sum, p) => sum + (p.amount || 0), 0);
    const expected = req.tenant.rent_amount || 0;
    const pending = Math.max(expected - collectedThisMonth, 0);

    res.json({
      success: true,
      payments,
      balance: {
        rent_amount: expected,
        collected_this_month: collectedThisMonth,
        pending_amount: pending,
        status: pending > 0 ? 'pending' : 'paid',
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Tenant portal: my maintenance requests
app.get('/api/tenant-portal/maintenance', requireTenantAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('maintenance_requests')
      .select('*')
      .eq('tenant_id', req.tenant.id)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, requests: data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Tenant portal: submit a new maintenance request
app.post('/api/tenant-portal/maintenance', requireTenantAuth, async (req, res) => {
  try {
    const { title, description } = req.body;
    if (!title) {
      return res.status(400).json({ error: 'title is required' });
    }

    const { data, error } = await supabase
      .from('maintenance_requests')
      .insert([
        {
          tenant_id: req.tenant.id,
          property_id: req.tenant.property_id,
          title,
          description: description || '',
          status: 'open',
          created_at: new Date(),
          updated_at: new Date(),
        },
      ])
      .select();

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, request: data[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Landlord view: all maintenance requests across your properties
app.get('/api/maintenance/landlord/:user_id', requireAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (req.user.id !== user_id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's maintenance requests" });
    }

    const { data: properties, error: propsError } = await supabase
      .from('properties')
      .select('id, address')
      .eq('user_id', user_id);
    if (propsError) return res.status(400).json({ error: propsError.message });

    const propertyIds = properties.map(p => p.id);
    if (propertyIds.length === 0) {
      return res.json({ success: true, requests: [] });
    }

    const { data: requests, error } = await supabase
      .from('maintenance_requests')
      .select('*, tenants(name, unit_label), properties(address)')
      .in('property_id', propertyIds)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, requests });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Landlord: update a maintenance request's status
app.put('/api/maintenance/:request_id', requireAuth, async (req, res) => {
  try {
    const { request_id } = req.params;
    const { status } = req.body;

    if (!MAINTENANCE_STATUSES.includes(status)) {
      return res.status(400).json({ error: `status must be one of: ${MAINTENANCE_STATUSES.join(', ')}` });
    }

    const { data: request, error: requestError } = await supabase
      .from('maintenance_requests')
      .select('property_id')
      .eq('id', request_id)
      .single();
    if (requestError || !request) {
      return res.status(404).json({ error: 'Maintenance request not found' });
    }

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', request.property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found for this request' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this property' });
    }

    const { data, error } = await supabase
      .from('maintenance_requests')
      .update({ status, updated_at: new Date() })
      .eq('id', request_id)
      .select();

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, request: data[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// SMS MESSAGING ROUTES
// ============================================

// Get all tenants across every property owned by a landlord (for the message-composer)
app.get('/api/tenants/landlord/:user_id', requireAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (req.user.id !== user_id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's tenants" });
    }

    const { data: properties, error: propsError } = await supabase
      .from('properties')
      .select('id, address')
      .eq('user_id', user_id);
    if (propsError) return res.status(400).json({ error: propsError.message });

    const propertyIds = properties.map(p => p.id);
    if (propertyIds.length === 0) {
      return res.json({ success: true, tenants: [] });
    }

    const { data: tenants, error: tenantsError } = await supabase
      .from('tenants')
      .select('*')
      .in('property_id', propertyIds);
    if (tenantsError) return res.status(400).json({ error: tenantsError.message });

    // Same per-tenant status/renewal computation as the dashboard route, so
    // any screen listing tenants (Properties, Communication Center) can show
    // paid/pending and "lease ends soon" without a second round trip.
    const tenantIds = (tenants || []).map(t => t.id);
    const startOfMonth = new Date(new Date().getFullYear(), new Date().getMonth(), 1);

    let payments = [];
    if (tenantIds.length) {
      const { data } = await supabase
        .from('payments')
        .select('*')
        .in('tenant_id', tenantIds)
        .gte('created_at', startOfMonth.toISOString());
      payments = data || [];
    }

    const collectedByTenant = {};
    payments
      .filter(p => p.status === 'paid')
      .forEach(p => {
        collectedByTenant[p.tenant_id] = (collectedByTenant[p.tenant_id] || 0) + (p.amount || 0);
      });

    const MS_PER_DAY = 24 * 60 * 60 * 1000;
    const today = new Date();

    const tenantsWithStatus = (tenants || []).map(t => {
      const collected = collectedByTenant[t.id] || 0;
      const expected = t.rent_amount || 0;
      const pending = Math.max(expected - collected, 0);
      const daysUntilLeaseEnd = t.lease_end_date
        ? Math.ceil((new Date(t.lease_end_date) - today) / MS_PER_DAY)
        : null;
      return {
        ...t,
        collected_this_month: collected,
        pending_amount: pending,
        status: pending > 0 ? 'pending' : 'paid',
        renewal_soon: daysUntilLeaseEnd !== null && daysUntilLeaseEnd >= 0 && daysUntilLeaseEnd <= 90,
        days_until_lease_end: daysUntilLeaseEnd,
      };
    });

    res.json({ success: true, tenants: tenantsWithStatus });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Send an SMS to one of your own tenants
app.post('/api/sms/send', requireAuth, async (req, res) => {
  try {
    const { tenant_id, message } = req.body;
    if (!tenant_id || !message) {
      return res.status(400).json({ error: 'Missing tenant_id or message' });
    }

    const { data: tenant, error: tenantError } = await supabase
      .from('tenants')
      .select('*')
      .eq('id', tenant_id)
      .single();
    if (tenantError || !tenant) {
      return res.status(404).json({ error: 'Tenant not found' });
    }

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', tenant.property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found for this tenant' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this tenant' });
    }

    const result = await sendSMS(tenant.phone, message, property.user_id);

    res.json({
      success: true,
      message_sid: result.sid,
      status: result.status,
    });
  } catch (error) {
    console.error('Send SMS error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get SMS history (sent + received) for a landlord
app.get('/api/sms/inbox/:user_id', requireAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (req.user.id !== user_id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's messages" });
    }

    const { data, error } = await supabase
      .from('sms_messages')
      .select('*')
      .eq('user_id', user_id)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, messages: data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// SMS quick-action templates (Rent Due Reminder, Late Payment Notice,
// Payment Received, etc.) -- shared across all landlords, not per-user, so
// no ownership check is needed here.
app.get('/api/sms/templates', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('sms_templates')
      .select('*')
      .order('template_name', { ascending: true });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, templates: data || [] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Twilio calls this when a tenant replies by SMS. Configure it as this number's
// "A message comes in" webhook (Twilio Console -> Phone Numbers -> your number).
app.post('/api/webhooks/twilio/inbound', express.urlencoded({ extended: false }), async (req, res) => {
  try {
    const from = req.body.From;
    const body = req.body.Body || '';
    const messageSid = req.body.MessageSid;

    const { data: tenant } = await supabase
      .from('tenants')
      .select('*')
      .eq('phone', from)
      .maybeSingle();

    let userId = null;
    if (tenant) {
      const { data: property } = await supabase
        .from('properties')
        .select('user_id')
        .eq('id', tenant.property_id)
        .single();
      userId = property?.user_id || null;
    }

    await supabase.from('sms_messages').insert([{
      user_id: userId,
      to_phone: from,
      message: body,
      status: 'received',
      twilio_sid: messageSid,
      created_at: new Date(),
    }]);

    res.set('Content-Type', 'text/xml');
    res.send('<?xml version="1.0" encoding="UTF-8"?><Response></Response>');
  } catch (error) {
    console.error('Twilio inbound webhook error:', error);
    res.set('Content-Type', 'text/xml');
    res.status(500).send('<?xml version="1.0" encoding="UTF-8"?><Response></Response>');
  }
});

// ============================================
// BILLING ROUTES
// ============================================

// Create a hosted Stripe Checkout session for the $150/mo plan with a 30-day trial.
// Card is collected now (required to auto-convert to the paid plan after the trial),
// but nothing is charged until the trial ends.
app.post('/api/create-checkout-session', requireAuth, async (req, res) => {
  try {
    // Identity comes from the verified session, never the request body --
    // otherwise anyone could start a trial checkout tagged with someone
    // else's user id.
    const userId = req.user.id;
    const email = req.user.email;

    if (!process.env.STRIPE_PRICE_ID) {
      return res.status(500).json({ error: 'STRIPE_PRICE_ID is not configured on the server' });
    }

    const frontendUrl = process.env.FRONTEND_URL || 'https://rentflow-frontend-phi.vercel.app';

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      customer_email: email,
      line_items: [
        {
          price: process.env.STRIPE_PRICE_ID,
          quantity: 1,
        },
      ],
      subscription_data: {
        trial_period_days: 30,
        metadata: { user_id: userId },
      },
      metadata: { user_id: userId },
      success_url: `${frontendUrl}/payment?checkout=success`,
      cancel_url: `${frontendUrl}/payment?checkout=cancelled`,
    });

    res.json({ success: true, url: session.url, sessionId: session.id });
  } catch (error) {
    console.error('Create checkout session error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Create subscription
app.post('/api/billing/subscribe', requireAuth, async (req, res) => {
  try {
    const { customer_id, email, payment_method_id } = req.body;

    if (!customer_id || !payment_method_id) {
      return res.status(400).json({ error: 'customer_id and payment_method_id are required' });
    }

    const { data: customerRow, error: customerLookupError } = await supabase
      .from('customers')
      .select('user_id')
      .eq('id', customer_id)
      .single();
    if (customerLookupError || !customerRow) {
      return res.status(404).json({ error: 'Customer not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (customerRow.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'This billing account does not belong to you' });
    }

    const stripeCustomer = await stripe.customers.create({
      email,
      payment_method: payment_method_id,
      invoice_settings: {
        default_payment_method: payment_method_id
      }
    });

    const subscription = await stripe.subscriptions.create({
      customer: stripeCustomer.id,
      items: [{
        price: process.env.STRIPE_PRICE_ID
      }],
      payment_settings: {
        payment_method_types: ['card']
      }
    });

    await supabase
      .from('customers')
      .update({
        stripe_customer_id: stripeCustomer.id,
        stripe_subscription_id: subscription.id,
        subscription_status: 'active'
      })
      .eq('id', customer_id);

    res.json({
      success: true,
      subscription: subscription,
      client_secret: subscription.latest_invoice?.payment_intent?.client_secret
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get billing history
app.get('/api/billing/invoices/:customer_id', requireAuth, async (req, res) => {
  try {
    const { customer_id } = req.params;

    const { data: customer } = await supabase
      .from('customers')
      .select('stripe_customer_id, user_id')
      .eq('id', customer_id)
      .single();

    if (!customer?.stripe_customer_id) {
      return res.status(400).json({ error: 'No billing account found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (customer.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'This billing account does not belong to you' });
    }

    const invoices = await stripe.invoices.list({
      customer: customer.stripe_customer_id
    });

    res.json({ success: true, invoices: invoices.data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Webhook for Stripe events
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const sig = req.headers['stripe-signature'];
    const event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );

    if (event.type === 'invoice.payment_succeeded') {
      const invoice = event.data.object;
      await supabase
        .from('customers')
        .update({ subscription_status: 'active' })
        .eq('stripe_customer_id', invoice.customer);
    }

    if (event.type === 'invoice.payment_failed') {
      const invoice = event.data.object;
      await supabase
        .from('customers')
        .update({ subscription_status: 'past_due' })
        .eq('stripe_customer_id', invoice.customer);
    }

    res.json({ received: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============================================
// HELPER FUNCTIONS
// ============================================

async function generatePaymentConfirmationMessage(tenantName, amount) {
  const message = await anthropic.messages.create({
    model: 'claude-opus-5',
    max_tokens: 100,
    messages: [
      {
        role: 'user',
        content: `Write a brief, friendly SMS confirmation message (under 160 characters) confirming a rent payment. Tenant name: ${tenantName}. Amount: $${amount}. Be warm and professional.`
      }
    ]
  });

  return message.content[0].text;
}

async function sendSMS(phone, message, user_id) {
  try {
    const result = await twilioClient.messages.create({
      body: message,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phone
    });

    await supabase
      .from('sms_messages')
      .insert([
        {
          user_id,
          to_phone: phone,
          message,
          status: result.status,
          twilio_sid: result.sid,
          created_at: new Date()
        }
      ]);

    return result;
  } catch (error) {
    console.error('SMS error:', error);
    throw error;
  }
}

function generateReceipt(tenantName, amount, paymentDate, paymentMethod) {
  return {
    tenant_name: tenantName,
    amount,
    payment_date: paymentDate,
    payment_method: paymentMethod,
    receipt_number: `REC-${Date.now()}`,
    timestamp: new Date()
  };
}

// ============================================
// DASHBOARD ROUTES
// ============================================

app.get('/api/dashboard/:user_id', requireAuth, async (req, res) => {
  try {
    const { user_id } = req.params;

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (req.user.id !== user_id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's dashboard" });
    }

    const { data: properties } = await supabase
      .from('properties')
      .select('*')
      .eq('user_id', user_id);

    const propertyIds = properties.map(p => p.id);

    const { data: tenants } = await supabase
      .from('tenants')
      .select('*')
      .in('property_id', propertyIds.length ? propertyIds : ['00000000-0000-0000-0000-000000000000']);

    const tenantIds = tenants.map(t => t.id);
    const startOfMonth = new Date(new Date().getFullYear(), new Date().getMonth(), 1);

    // Only this landlord's own tenants' payments -- previously this summed every
    // landlord's payments for the month, inflating everyone's "collected" total.
    let payments = [];
    if (tenantIds.length) {
      const { data } = await supabase
        .from('payments')
        .select('*')
        .in('tenant_id', tenantIds)
        .gte('created_at', startOfMonth.toISOString());
      payments = data || [];
    }

    // Rent lives on the tenant/lease now, not the property -- a duplex or
    // triplex has one rent per unit, not one for the whole building.
    // rent_amount and payment amounts are both stored in cents.
    const totalExpected = tenants.reduce((sum, t) => sum + (t.rent_amount || 0), 0);
    const totalCollected = payments
      .filter(p => p.status === 'paid')
      .reduce((sum, p) => sum + (p.amount || 0), 0);

    // Per-tenant collected/pending, so each unit shows its own status.
    const collectedByTenant = {};
    payments
      .filter(p => p.status === 'paid')
      .forEach(p => {
        collectedByTenant[p.tenant_id] = (collectedByTenant[p.tenant_id] || 0) + (p.amount || 0);
      });

    const MS_PER_DAY = 24 * 60 * 60 * 1000;
    const today = new Date();

    const tenantsWithStatus = tenants.map(t => {
      const collected = collectedByTenant[t.id] || 0;
      const expected = t.rent_amount || 0;
      const pending = Math.max(expected - collected, 0);
      const daysUntilLeaseEnd = t.lease_end_date
        ? Math.ceil((new Date(t.lease_end_date) - today) / MS_PER_DAY)
        : null;
      return {
        ...t,
        collected_this_month: collected,
        pending_amount: pending,
        status: pending > 0 ? 'pending' : 'paid',
        // Quebec's lease non-renewal / rent-increase notice window opens
        // 3-6 months before the lease ends -- flag inside 90 days so it's
        // never missed by accident.
        renewal_soon: daysUntilLeaseEnd !== null && daysUntilLeaseEnd >= 0 && daysUntilLeaseEnd <= 90,
        days_until_lease_end: daysUntilLeaseEnd,
      };
    });

    const tenantsByProperty = {};
    tenantsWithStatus.forEach(t => {
      if (!tenantsByProperty[t.property_id]) tenantsByProperty[t.property_id] = [];
      tenantsByProperty[t.property_id].push(t);
    });

    const propertiesWithStatus = properties.map(p => {
      const propTenants = tenantsByProperty[p.id] || [];
      const collected = propTenants.reduce((sum, t) => sum + t.collected_this_month, 0);
      const expected = propTenants.reduce((sum, t) => sum + (t.rent_amount || 0), 0);
      const pending = Math.max(expected - collected, 0);
      return {
        ...p,
        tenants: propTenants,
        collected_this_month: collected,
        pending_amount: pending,
        status: pending > 0 ? 'pending' : 'paid',
      };
    });

    const renewalsSoon = tenantsWithStatus.filter(t => t.renewal_soon);

    res.json({
      success: true,
      summary: {
        total_properties: properties.length,
        total_tenants: tenants.length,
        total_expected_this_month: totalExpected,
        total_collected_this_month: totalCollected,
        pending_amount: Math.max(totalExpected - totalCollected, 0),
        late_payments: payments.filter(p => p.status === 'late').length,
        leases_renewing_soon: renewalsSoon.length
      },
      properties: propertiesWithStatus,
      tenants: tenantsWithStatus,
      renewals_soon: renewalsSoon,
      payments
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// ADMIN ROUTES
// ============================================

// Platform-wide stats + user list, for the Admin Dashboard only.
// Uses the service-role client server-side -- this can never be called safely from the browser.
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const { data: usersPage, error: usersError } = await supabase.auth.admin.listUsers({ perPage: 200 });
    if (usersError) throw usersError;

    const { data: properties, error: propsError } = await supabase.from('properties').select('*');
    if (propsError) throw propsError;

    const { data: tenants, error: tenantsError } = await supabase.from('tenants').select('*');
    if (tenantsError) throw tenantsError;

    const { data: payments, error: paymentsError } = await supabase.from('payments').select('*');
    if (paymentsError) throw paymentsError;

    const users = usersPage.users.map(u => ({
      id: u.id,
      email: u.email,
      created_at: u.created_at,
      confirmed_at: u.email_confirmed_at,
    }));

    res.json({
      success: true,
      stats: {
        totalUsers: users.length,
        totalProperties: properties.length,
        totalTenants: tenants.length,
        totalRevenue: payments.reduce((sum, p) => sum + (p.amount || 0), 0),
      },
      users,
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// HEALTH CHECK
// ============================================

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date() });
});

// ============================================
// ERROR HANDLING
// ============================================

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

// ============================================
// START SERVER
// ============================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Rentflow backend running on port ${PORT}`);
});

module.exports = app;
