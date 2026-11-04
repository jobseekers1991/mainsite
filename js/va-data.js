/* ================================
   Jobseekers.ph — shared vocabulary for AI Match
   SHIFTS and SKILL_SYNONYMS are consumed by ai-match.html to parse the
   client's role description. The actual VA directory lives server-side
   (data/vas.json via /api/vas) — there is no hardcoded VA array here.
   ================================ */

// Client time zones, and the Philippine hours a VA works to cover them
const SHIFTS = {
  'us-east': { label: 'US Eastern (EST)', ph: 'PH night shift, 9PM–5AM', cls: 'night', icon: 'fa-moon' },
  'us-west': { label: 'US Pacific (PST)', ph: 'PH graveyard, 12AM–8AM', cls: 'night', icon: 'fa-moon' },
  'uk':      { label: 'UK business hours', ph: 'PH evening, 4PM–1AM', cls: 'uk', icon: 'fa-cloud-moon' },
  'au':      { label: 'AU business hours', ph: 'PH morning, 6AM–2PM', cls: 'au', icon: 'fa-sun' },
  'ph':      { label: 'PH / Asia daytime', ph: 'PH day, 8AM–5PM', cls: '', icon: 'fa-sun' },
};

// Words a client might type → canonical skill vocabulary used by the matcher
const SKILL_SYNONYMS = {
  'admin': ['admin', 'administrative', 'assistant', 'ea', 'executive', 'virtual assistant', 'general va', 'errands'],
  'calendar': ['calendar', 'schedule', 'scheduling', 'meetings', 'appointments'],
  'email': ['email', 'inbox', 'gmail', 'outlook'],
  'crm': ['crm', 'hubspot', 'salesforce', 'pipedrive', 'podio', 'follow up boss'],
  'travel': ['travel', 'flights', 'booking', 'itinerary'],
  'data entry': ['data entry', 'spreadsheet', 'spreadsheets', 'excel', 'google sheets', 'typing'],
  'project management': ['project management', 'asana', 'trello', 'clickup', 'monday', 'project'],
  'social media': ['social media', 'instagram', 'tiktok', 'facebook', 'linkedin', 'pinterest', 'smm', 'social'],
  'content creation': ['content creation', 'reels', 'posts', 'content calendar', 'content'],
  'graphic design': ['graphic design', 'design', 'graphics', 'canva', 'photoshop', 'illustrator', 'logo', 'thumbnails'],
  'analytics': ['analytics', 'reporting', 'metrics', 'ga4', 'insights', 'kpi'],
  'copywriting': ['copywriting', 'copy', 'captions', 'ad copy', 'sales page'],
  'bookkeeping': ['bookkeeping', 'bookkeeper', 'books', 'quickbooks', 'xero', 'qbo'],
  'accounting': ['accounting', 'accountant', 'cpa', 'tax', 'financial'],
  'payroll': ['payroll', 'gusto'],
  'reconciliation': ['reconciliation', 'reconcile', 'bank rec'],
  'invoicing': ['invoice', 'invoicing', 'billing', 'accounts receivable', 'ar', 'ap', 'accounts payable'],
  'content writing': ['content writing', 'writer', 'writing', 'articles', 'blog posts', 'blog'],
  'seo': ['seo', 'search engine', 'keywords', 'ranking', 'surferseo', 'semrush', 'ahrefs'],
  'email marketing': ['email marketing', 'newsletter', 'klaviyo', 'mailchimp', 'email campaigns'],
  'research': ['research', 'lead list', 'market research'],
  'video editing': ['video editing', 'video', 'youtube', 'premiere', 'capcut', 'editing', 'reels editing'],
  'branding': ['branding', 'brand', 'brand identity'],
  'customer support': ['customer support', 'customer service', 'support', 'csr', 'helpdesk', 'tickets'],
  'live chat': ['live chat', 'chat support', 'chat'],
  'phone support': ['phone', 'calls', 'inbound calls', 'phone support'],
  'ticketing': ['zendesk', 'freshdesk', 'gorgias', 'intercom', 'ticketing'],
  'digital marketing': ['digital marketing', 'marketing', 'growth'],
  'paid ads': ['ads', 'paid ads', 'google ads', 'facebook ads', 'meta ads', 'ppc', 'media buying'],
  'lead generation': ['lead generation', 'leads', 'lead gen', 'prospecting', 'outreach'],
  'ecommerce': ['ecommerce', 'e-commerce', 'online store', 'shopify', 'amazon', 'etsy', 'store'],
  'product listings': ['product listings', 'listings', 'product upload', 'listing'],
  'inventory': ['inventory', 'stock'],
  'order processing': ['order processing', 'orders', 'fulfillment', 'returns'],
  'cold calling': ['cold calling', 'cold call', 'cold caller', 'dialer'],
  'appointment setting': ['appointment setting', 'appointment setter', 'book appointments', 'booking calls'],
  'web development': ['web development', 'developer', 'website', 'web dev', 'landing page', 'html', 'wordpress'],
  'wordpress': ['wordpress', 'elementor', 'wp'],
  'shopify': ['shopify'],
  'medical admin': ['medical', 'clinic', 'healthcare', 'dental', 'patients', 'hipaa', 'ehr'],
  'insurance verification': ['insurance', 'verification', 'billing codes'],
  'real estate': ['real estate', 'realtor', 'property', 'listings agent'],
};
