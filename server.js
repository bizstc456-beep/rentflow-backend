// Rental Property Assistant - Express Backend
// Deploy to Railway, Fly.io, or Vercel Functions
// Dependencies: npm install express cors dotenv supabase-js twilio axios node-cron

import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import twilio from 'twilio';
import Anthropic from '@anthropic-ai/sdk';
import cron from 'node-cron';
import crypto from 'crypto';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Initialize clients
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

const claudeClient = new Anthropic({
  apiKey: process.env.CLAUDE_API_KEY,
});

app.use(cors());
app.use(express.json());

// ========== PROPERTIES ==========

// Get all properties for customer
app.get('/api/properties', async (req, res) => {
  try {
    const customerId = req.headers['x-customer-id'];
    const { data, error } = await supabase
      .from('properties')
      .select('*')
      .eq('customer_id', customerId);
    
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create property
app.post('/api/properties', async (req, res) => {
  try {
    const { address, units, customerId } = req.body;
    const { data, error } = await supabase
      .from('properties')
      .insert([
        {
          address,
          units,
          customer_id: customerId,
          created_at: new Date().toISOString(),
        },
      ])
      .select();
    
    if (error) throw error;
    res.json(data[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== TENANTS ==========

app.post('/api/tenants', async (req, res) => {
  try {
    const { propertyId, name, phone, email, rentDueDay, customerId } = req.body;
    
    const { data, error } = await supabase
      .from('tenants')
      .insert([
        {
          property_id: propertyId,
          name,
          phone,
          email,
          rent_due_day: rentDueDay,
          customer_id: customerId,
          created_at: new Date().toISOString(),
        },
      ])
      .select();
    
    if (error) throw error;
    res.json(data[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get tenants for property
app.get('/api/properties/:propertyId/tenants', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('tenants')
      .select('*')
      .eq('property_id', req.params.propertyId);
    
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== AUTOMATED MESSAGING ==========

// Generate rental reminder via Claude
async function generateTenantMessage(tenant, messageType = 'rent_reminder') {
  try {
    const prompts = {
      rent_reminder: `Generate a professional, friendly rent reminder SMS for a tenant named ${tenant.name}. Rent is due on the ${tenant.rent_due_day}th of the month. Keep it under 160 characters for SMS. No emojis.`,
      
      maintenance_request: `Generate a professional maintenance request confirmation SMS for tenant ${tenant.name}. Confirm we received their request and will respond within 24 hours. Keep it under 160 characters.`,
      
      late_payment: `Generate a firm but professional late payment reminder SMS for tenant ${tenant.name}. Rent was due on the ${tenant.rent_due_day}th. Request payment within 3 days. Keep it under 160 characters.`,
    };

    const message = await claudeClient.messages.create({
      model: 'claude-3-5-sonnet-20241022',
      max_tokens: 100,
      messages: [
        {
          role: 'user',
          content: prompts[messageType],
        },
      ],
    });

    return message.content[0].text;
  } catch (error) {
    console.error('Claude API error:', error);
    throw error;
  }
}

// Send SMS to tenant
async function sendSMSToTenant(tenant, message) {
  try {
    const result = await twilioClient.messages.create({
      body: message,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: tenant.phone,
    });

    // Log in database
    await supabase
      .from('messages')
      .insert([
        {
          tenant_id: tenant.id,
          message_type: 'sms',
          body: message,
          status: 'sent',
          twilio_sid: result.sid,
          sent_at: new Date().toISOString(),
        },
      ]);

    return result.sid;
  } catch (error) {
    console.error('Twilio SMS error:', error);
    throw error;
  }
}

// Trigger rent reminder
app.post('/api/messages/send-rent-reminder', async (req, res) => {
  try {
    const { tenantId } = req.body;
    
    const { data: tenant, error } = await supabase
      .from('tenants')
      .select('*')
      .eq('id', tenantId)
      .single();
    
    if (error) throw error;

    const message = await generateTenantMessage(tenant, 'rent_reminder');
    const sid = await sendSMSToTenant(tenant, message);

    res.json({ success: true, sid, message });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== SCHEDULING (CRON) ==========

// Run daily at 9 AM to send rent reminders
cron.schedule('0 9 * * *', async () => {
  try {
    console.log('Running daily rent reminder scheduler...');
    
    // Get all tenants with rent due today
    const today = new Date();
    const dueDay = today.getDate();
    
    const { data: tenants, error } = await supabase
      .from('tenants')
      .select('*')
      .eq('rent_due_day', dueDay)
      .eq('active', true);

    if (error) throw error;

    for (const tenant of tenants) {
      try {
        const message = await generateTenantMessage(tenant, 'rent_reminder');
        await sendSMSToTenant(tenant, message);
        console.log(`Sent reminder to ${tenant.name}`);
      } catch (err) {
        console.error(`Failed to send to ${tenant.name}:`, err.message);
      }
    }
  } catch (err) {
    console.error('Scheduler error:', err);
  }
});

// ========== STRIPE WEBHOOK ==========

// Verify Stripe signature (raw body middleware)
app.post('/api/webhooks/stripe', express.raw({type: 'application/json'}), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  
  try {
    const event = JSON.parse(req.body);
    
    // Verify signature (simplified - in production use Stripe client)
    if (event.type === 'charge.succeeded') {
      const { customer_email } = event.data.object;
      
      // Log successful payment
      await supabase
        .from('payments')
        .insert([
          {
            stripe_charge_id: event.data.object.id,
            amount: event.data.object.amount / 100,
            customer_email,
            created_at: new Date().toISOString(),
          },
        ]);
    }
    
    res.json({ received: true });
  } catch (err) {
    res.status(400).json({ error: 'Webhook error' });
  }
});

// ========== HEALTH CHECK ==========

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`Rental Assistant API running on port ${PORT}`);
});
