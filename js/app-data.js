/* ================================
   Jobseekers.ph - Shared app data & storage
   Sample jobs plus the state for applications, messages, the client
   dashboard and the admin queues. Everything is kept in this browser's
   localStorage until a real backend replaces Store.
   ================================ */

const Store = {
  get(key, seed) {
    try {
      const raw = localStorage.getItem(key);
      if (raw) return JSON.parse(raw);
    } catch (e) {}
    const value = typeof seed === 'function' ? seed() : seed;
    Store.set(key, value);
    return value;
  },
  set(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); } catch (e) {}
  },
};

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const fmtDay = t => new Date(t).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
const DAY_MS = 86400000;
const daysAgo = n => Date.now() - n * DAY_MS;

const SHIFT_LABELS = {
  'us-east': { label: 'US Eastern hours', ph: 'PH 9PM–5AM', icon: 'fa-moon' },
  'us-west': { label: 'US Pacific hours', ph: 'PH 12AM–8AM', icon: 'fa-moon' },
  'uk': { label: 'UK hours', ph: 'PH 4PM–1AM', icon: 'fa-cloud-moon' },
  'au': { label: 'AU hours', ph: 'PH 6AM–2PM', icon: 'fa-sun' },
  'ph': { label: 'Flexible / PH daytime', ph: 'PH 8AM–5PM', icon: 'fa-sun' },
};

const JOBS = [
  {
    id: 'exec-assistant', title: 'Executive Virtual Assistant (Full-Time)', company: 'Carter Digital Agency', emoji: '🚀', logoBg: 'rgba(79,70,229,0.08)',
    rate: '$6–$10/hr', rateMax: 10, type: 'Full-Time', hours: '40 hrs/week', shift: 'us-east', posted: 'Posted 2 hours ago', applicants: 14, trial: true,
    trust: 96, verified: true, skills: ['Calendar Mgmt', 'Email', 'CRM', 'HubSpot'],
    summary: 'Looking for a dedicated EA to manage executive calendar, handle email correspondence, coordinate travel, and support daily operations. CRM experience preferred.',
    responsibilities: ['Manage the CEO\'s calendar across three time zones', 'Keep the inbox at zero and draft replies for review', 'Book travel and prepare itineraries', 'Update deals and contacts in HubSpot', 'Send a short end-of-day report'],
    requirements: ['2+ years as an EA or admin VA', 'Strong written English (English test 85+)', 'Available 9AM–5PM US Eastern (PH night shift)', 'Reliable internet with a backup plan'],
    screening: ['Tell us about a time you managed a very busy calendar. What was your system?', 'What is your backup plan if there is a brownout during your shift?'],
    client: { name: 'James Carter', location: 'New York, USA', since: 'Member since 2023', hires: 9, spent: '$48K+', rating: 4.9, vaReviews: 31, details: ['Payment verified', '88% hire rate', 'Always paid on time'] },
  },
  {
    id: 'social-media-manager', title: 'Social Media Manager — E-commerce Brand', company: 'Bloom & Co.', emoji: '📱', logoBg: 'rgba(236,72,153,0.08)',
    rate: '$8–$12/hr', rateMax: 12, type: 'Part-Time', hours: '20 hrs/week', shift: 'uk', posted: 'Posted 5 hours ago', applicants: 38, trial: true,
    trust: 91, verified: true, skills: ['Instagram', 'TikTok', 'Canva', 'Analytics'],
    summary: 'Seeking a creative SMM to manage our Instagram, TikTok, and Pinterest. Must be able to create engaging content, design graphics in Canva, and analyze performance metrics.',
    responsibilities: ['Plan a monthly content calendar', 'Design posts and short videos in Canva / CapCut', 'Write captions and reply to comments and DMs', 'Report monthly reach, engagement and sales'],
    requirements: ['Portfolio of brand accounts you have grown', 'Comfortable on camera tools and trends', 'Available UK business hours'],
    screening: ['Share a link to an account you grew and what you did.', 'How would you plan our first two weeks?'],
    client: { name: 'Sophie Anderson', location: 'London, UK', since: 'Member since 2024', hires: 4, spent: '$12K+', rating: 4.8, vaReviews: 12, details: ['Payment verified', '75% hire rate'] },
  },
  {
    id: 'bookkeeper', title: 'Online Bookkeeper — QuickBooks & Xero Expert', company: 'TechForge Solutions', emoji: '💼', logoBg: 'rgba(16,185,129,0.08)',
    rate: '$10–$15/hr', rateMax: 15, type: 'Full-Time', hours: '40 hrs/week', shift: 'us-east', posted: 'Posted 1 day ago', applicants: 22, trial: false,
    trust: 94, verified: true, skills: ['QuickBooks', 'Xero', 'Reconciliation', 'Payroll'],
    summary: 'We need an experienced bookkeeper to manage accounts payable/receivable, bank reconciliations, and prepare monthly financial reports. QuickBooks Online certification is a plus.',
    responsibilities: ['Reconcile 6 bank and card accounts weekly', 'Run AP/AR and chase overdue invoices', 'Prepare month-end P&L and balance sheet', 'Process bi-weekly payroll in Gusto'],
    requirements: ['3+ years bookkeeping for US companies', 'QuickBooks Online (certification a plus)', 'Detail-oriented and confidential'],
    screening: ['Which accounting software have you used, and for how long?', 'Walk us through how you close a month.'],
    client: { name: 'Michael Torres', location: 'Austin, USA', since: 'Member since 2022', hires: 6, spent: '$70K+', rating: 5.0, vaReviews: 9, details: ['Business verified', '92% hire rate'] },
  },
  {
    id: 'seo-writer', title: 'SEO Content Writer — Health & Wellness Niche', company: 'Vitality Health Media', emoji: '✍️', logoBg: 'rgba(245,158,11,0.08)',
    rate: '$7–$9/hr', rateMax: 9, type: 'Part-Time', hours: '20 hrs/week', shift: 'ph', posted: 'Posted 1 day ago', applicants: 61, trial: true,
    trust: 64, verified: false, skills: ['SEO Writing', 'WordPress', 'Health Niche'],
    summary: 'Looking for a skilled content writer to produce 4–6 SEO-optimized blog posts per week on health, fitness, and wellness topics. SurferSEO or Clearscope experience preferred.',
    responsibilities: ['Write 4–6 articles (1,500+ words) per week', 'Optimize with SurferSEO', 'Upload and format in WordPress'],
    requirements: ['Published health or wellness writing samples', 'Strong research and citation habits'],
    screening: ['Share two writing samples.', 'How do you research a medical topic accurately?'],
    client: { name: 'Vitality Health Media', location: 'Singapore', since: 'Joined this month', hires: 0, spent: '$0', rating: null, vaReviews: 0, details: ['Payment method pending', 'New client: no hires yet'] },
  },
  {
    id: 'graphic-designer', title: 'Graphic Designer & Brand Identity Specialist', company: 'Nova Branding Co.', emoji: '🎨', logoBg: 'rgba(99,102,241,0.08)',
    rate: '$10–$14/hr', rateMax: 14, type: 'Full-Time', hours: '40 hrs/week', shift: 'us-west', posted: 'Posted 2 days ago', applicants: 45, trial: true,
    trust: 89, verified: true, skills: ['Photoshop', 'Illustrator', 'Figma', 'Canva Pro'],
    summary: 'Design logos, brand kits, social media graphics, and marketing materials. Must have a strong portfolio and proficiency in Adobe Suite and Figma.',
    responsibilities: ['Create brand identities for agency clients', 'Design social and ad creatives', 'Prepare print-ready files'],
    requirements: ['Strong portfolio', 'Adobe Suite and Figma', 'Available US Pacific hours'],
    screening: ['Link your portfolio.', 'Which brand project are you proudest of, and why?'],
    client: { name: 'Nova Branding Co.', location: 'Los Angeles, USA', since: 'Member since 2024', hires: 5, spent: '$22K+', rating: 4.7, vaReviews: 8, details: ['Payment verified', '70% hire rate'] },
  },
  {
    id: 'ecommerce-va', title: 'eCommerce VA — Shopify & Amazon Expert', company: 'ShopEase Global', emoji: '🛒', logoBg: 'rgba(239,68,68,0.08)',
    rate: '$8–$11/hr', rateMax: 11, type: 'Full-Time', hours: '40 hrs/week', shift: 'au', posted: 'Posted 2 days ago', applicants: 79, trial: false,
    trust: 71, verified: false, skills: ['Shopify', 'Amazon FBA', 'Product Listings'],
    summary: 'Manage product listings, inventory, customer inquiries, and order processing for our Shopify and Amazon stores. Experience with Jungle Scout or Helium 10 is a bonus.',
    responsibilities: ['Create and optimize product listings', 'Track inventory and reorder points', 'Answer customer emails and process returns'],
    requirements: ['1+ year Shopify or Amazon experience', 'Available AU business hours'],
    screening: ['Which Shopify apps have you used?', 'How would you handle a late-delivery complaint?'],
    client: { name: 'ShopEase Global', location: 'Sydney, Australia', since: 'Member since 2025', hires: 2, spent: '$3K+', rating: null, vaReviews: 0, details: ['Card verified', '2 hires', 'No VA reviews yet'] },
  },
  {
    id: 'customer-support', title: 'Customer Support Specialist (Zendesk)', company: 'SupportGenius Inc.', emoji: '💬', logoBg: 'rgba(16,185,129,0.08)',
    rate: '$6–$8/hr', rateMax: 8, type: 'Full-Time', hours: '40 hrs/week', shift: 'us-west', posted: 'Posted 3 days ago', applicants: 33, trial: true,
    trust: 97, verified: true, skills: ['Zendesk', 'Live Chat', 'Email Support', 'Phone Support'],
    summary: 'Handle customer inquiries via email, live chat, and phone. Must have excellent English communication skills and experience with Zendesk or Freshdesk.',
    responsibilities: ['Answer tickets and live chats within SLA', 'Escalate bugs to the product team', 'Keep macros and help articles up to date'],
    requirements: ['1+ year in customer support', 'English test 90+', 'Available US Pacific hours'],
    screening: ['Describe how you calmed down an angry customer.', 'What CSAT score have you maintained?'],
    client: { name: 'Sarah Liu', location: 'San Francisco, USA', since: 'Member since 2021', hires: 18, spent: '$120K+', rating: 4.9, vaReviews: 44, details: ['Business verified', '95% hire rate', 'Always paid on time'] },
  },
];

const jobById = id => JOBS.find(j => j.id === id);

/* ---------- VA side: applications ---------- */
const APP_STATUS = {
  submitted: { label: 'Submitted', pill: 'pending' },
  viewed: { label: 'Viewed', pill: 'viewed' },
  interview: { label: 'Interview', pill: 'active' },
  trial: { label: 'Trial offer', pill: 'hired' },
  trialing: { label: 'Trial in progress', pill: 'active' },
  hired: { label: 'Hired', pill: 'hired' },
  rejected: { label: 'Not selected', pill: 'rejected' },
  withdrawn: { label: 'Withdrawn', pill: 'closed' },
};

const seedApplications = () => [
  { jobId: 'exec-assistant', status: 'interview', date: daysAgo(2), rate: 9, cover: 'I have 6 years supporting US executives on the night shift…' },
  { jobId: 'customer-support', status: 'trial', date: daysAgo(4), rate: 8, cover: 'I keep a 97% CSAT on Zendesk…', trial: { days: 3, hours: 4, scope: 'Answer 40 practice tickets and 2 live-chat shifts' } },
  { jobId: 'social-media-manager', status: 'viewed', date: daysAgo(5), rate: 10, cover: 'I grew a skincare brand from 2K to 60K followers…' },
  { jobId: 'bookkeeper', status: 'rejected', date: daysAgo(12), rate: 12, cover: 'Two years of QuickBooks experience…' },
];

const APPLY_LIMIT = 5; // Basic plan: applications per month
const applicationsThisMonth = apps => apps.filter(a => new Date(a.date).getMonth() === new Date().getMonth() && a.status !== 'withdrawn').length;

/* ---------- Messages ---------- */
const OFF_PLATFORM_RE = /\b(telegram|whatsapp|viber|signal|wechat|gcash me|pay (you )?outside|outside (the )?(platform|jobseekers)|paypal me|send (me )?(your )?(otp|password|bank))\b/i;

const seedThreads = role => role === 'client' ? [
  { id: 'maria-santos', name: 'Maria Santos', img: 47, sub: 'Executive VA · Hired', unread: 1, messages: [
    { me: false, text: 'Good morning James! Today\'s EOD report is in your inbox. The Denver trip is fully booked 🎉', t: daysAgo(0.05) },
  ] },
  { id: 'kim-navarro', name: 'Kim Navarro', img: 44, sub: 'Applicant · Executive VA', unread: 1, messages: [
    { me: true, text: 'Hi Kim, thanks for applying! Could you do a 3-day paid trial next week?', t: daysAgo(1) },
    { me: false, text: 'Yes po, I would love that! I\'m available on your EST hours. Please send the trial scope when ready.', t: daysAgo(0.9) },
  ] },
  { id: 'grace-villanueva', name: 'Grace Villanueva', img: 25, sub: 'Paid trial · Support', unread: 0, messages: [
    { me: false, text: 'Trial day 2 done: 31 tickets solved, 0 escalations. Notes are in the shared doc.', t: daysAgo(1.5) },
  ] },
] : [
  { id: 'james-carter', name: 'James Carter', img: 33, sub: 'Carter Digital Agency · Executive VA', unread: 2, messages: [
    { me: false, text: 'Hi Maria! I reviewed your application and loved your calendar-management example.', t: daysAgo(0.02) },
    { me: false, text: 'Are you free for a 20-minute video call tomorrow at 9:30 PM your time?', t: daysAgo(0.015) },
  ] },
  { id: 'sarah-liu', name: 'Sarah Liu', img: 49, sub: 'SupportGenius Inc. · Paid trial offer', unread: 1, messages: [
    { me: false, text: 'Can you start on Monday? The job is 3 days × 4 hours as a paid trial. Details are in My Applications.', t: daysAgo(0.05) },
  ] },
  { id: 'robert-kim', name: 'Robert Kim', img: 60, sub: 'Bloom & Co. · Social Media Manager', unread: 0, messages: [
    { me: true, text: 'Hello Robert, I just applied for the Social Media Manager role. Happy to share more samples!', t: daysAgo(0.2) },
    { me: false, text: 'Thanks for applying. We\'ll get back to you.', t: daysAgo(0.13) },
  ] },
  { id: 'hr-global', name: 'HR Global Jobs', img: 15, sub: 'Account suspended', unread: 0, suspended: true, messages: [
    { me: false, text: 'Congrats you are hired!! Pay ₱1,500 training fee then message us on Telegram @hr_global_jobs', t: daysAgo(3) },
  ] },
];

/* ---------- Client side ---------- */
const seedClient = () => ({
  jobs: [
    { id: 'exec-assistant', title: 'Executive Virtual Assistant (Full-Time)', status: 'Open', posted: daysAgo(0.1) },
    { id: 'cold-caller', title: 'Real Estate Cold Caller (Part-Time)', status: 'Open', posted: daysAgo(6) },
  ],
  applicants: [
    { vaId: 'maria-santos', jobId: 'exec-assistant', status: 'hired', rate: 9, match: 96, date: daysAgo(2), cover: 'I have 6 years supporting US executives on the night shift. At my last client I cut the CEO\'s meeting load by 30% with a weekly calendar audit.', answers: ['I colour-code by priority and block focus time first, then batch meetings into two windows a day.', 'UPS for my PC and modem (4+ hours) plus a Globe LTE pocket WiFi.'] },
    { vaId: 'kim-navarro', jobId: 'exec-assistant', status: 'shortlisted', rate: 6, match: 84, date: daysAgo(1), cover: 'Newer VA but certified in VA Foundations and Google Workspace. I was a bank teller for 4 years, so I\'m careful with details and deadlines.', answers: ['I used Google Calendar with color codes for a 12-person branch schedule.', 'UPS + Smart LTE backup. I\'m Brownout-ready verified.'] },
    { vaId: 'paolo-garcia', jobId: 'exec-assistant', status: 'new', rate: 7, match: 78, date: daysAgo(0.5), cover: 'Admin VA with CRM experience in Podio and HubSpot. I work EST nights already.', answers: ['Shared calendars in Google Workspace for a real estate team of 8.', 'Generator at home and a Smart prepaid modem.'] },
    { vaId: 'bea-ocampo', jobId: 'exec-assistant', status: 'new', rate: 9, match: 74, date: daysAgo(0.3), cover: 'I schedule 60+ patient appointments a day for a US clinic. Happy to bring that discipline to an executive\'s calendar.', answers: ['I use time-blocking and a daily confirmation sweep.', 'UPS (2 hrs) and a DITO SIM hotspot.'] },
    { vaId: 'leo-bautista', jobId: 'exec-assistant', status: 'rejected', rate: 13, match: 52, date: daysAgo(1.2), cover: 'Marketing specialist looking to move into EA work.', answers: ['—', 'No backup yet.'] },
    { vaId: 'grace-villanueva', jobId: 'cold-caller', status: 'trial', rate: 7, match: 81, date: daysAgo(5), cover: 'Strong phone voice, 4 years in support calls.', answers: ['—', 'UPS and LTE backup.'] },
  ],
  hires: [
    { vaId: 'maria-santos', role: 'Executive Virtual Assistant', rate: 9, start: daysAgo(12), hoursWeek: 38.5 },
    { vaId: 'diana-flores', role: 'Shopify Store Assistant', rate: 10, start: daysAgo(64), hoursWeek: 20 },
  ],
  trials: [
    { id: 't1', vaId: 'grace-villanueva', role: 'Real Estate Cold Caller', days: 3, hours: 4, rate: 7, scope: 'Call 150 leads from the list, log results in Podio, book any interested sellers.', status: 'in-progress', day: 2 },
    { id: 't2', vaId: 'kim-navarro', role: 'Executive VA', days: 3, hours: 4, rate: 6, scope: 'Inbox cleanup (≈300 emails) and book 3 meetings from the waiting list.', status: 'pending-accept' },
  ],
  invoices: [
    { id: 'INV-2026-0101', vaId: 'maria-santos', period: 'Oct 12–18', hours: 38.5, rate: 9, status: 'due' },
    { id: 'INV-2026-0098', vaId: 'diana-flores', period: 'Oct 12–18', hours: 26, rate: 10, status: 'due', note: 'Logged 26h but contract is 20h/week' },
    { id: 'INV-2026-0087', vaId: 'diana-flores', period: 'Oct 5–11', hours: 20, rate: 10, status: 'paid' },
    { id: 'INV-2026-0076', vaId: 'maria-santos', period: 'Oct 5–11', hours: 37, rate: 9, status: 'paid' },
    { id: 'INV-2026-0065', vaId: 'diana-flores', period: 'Sep 28–Oct 4', hours: 20, rate: 10, status: 'paid' },
    { id: 'INV-2026-0054', vaId: 'maria-santos', period: 'Sep 28–Oct 4', hours: 39.5, rate: 9, status: 'paid' },
  ],
  replacements: [],
  // Talent Pool: saved VA ids across jobs
  favorites: ['bea-ocampo', 'paolo-garcia', 'kim-navarro'],
  // Scheduled interviews
  interviews: [
    { id: 'iv1', vaId: 'kim-navarro', jobId: 'exec-assistant', when: Date.now() + 1 * DAY_MS + 3 * 3600000, duration: 20, link: 'https://meet.google.com/abc-defg-hij', note: 'Walk through calendar workflow and brownout plan', status: 'upcoming' },
    { id: 'iv2', vaId: 'paolo-garcia', jobId: 'exec-assistant', when: Date.now() + 2 * DAY_MS + 1 * 3600000, duration: 30, link: 'https://zoom.us/j/8842103941', note: '', status: 'upcoming' },
    { id: 'iv3', vaId: 'bea-ocampo', jobId: 'exec-assistant', when: daysAgo(1), duration: 20, link: 'https://meet.google.com/past-abcd-xyz', note: 'Great culture fit', status: 'done' },
  ],
  // Reusable job post templates
  templates: [
    { id: 'tpl-ea', title: 'Executive VA (standard)', summary: 'Full-time EA for CEO calendar + inbox + travel. Night-shift (EST).', rate: '$6–$10/hr', shift: 'us-east', skills: ['Calendar Mgmt', 'Email', 'CRM'], screening: ['Describe your calendar-management system.', 'What is your backup plan for brownouts?'], used: 3 },
    { id: 'tpl-sdr', title: 'Appointment Setter (SDR)', summary: 'Cold-call US leads, log in HubSpot, book sales calls.', rate: '$7–$9/hr', shift: 'us-east', skills: ['Cold Calling', 'HubSpot', 'Lead Qualification'], screening: ['Share a short voice sample.', 'How many dials per hour do you average?'], used: 1 },
  ],
  // VA daily hours before an invoice is generated
  timesheets: [
    { vaId: 'maria-santos', day: daysAgo(0.3), hours: 7.5, note: 'Inbox + calendar + draft Denver itinerary', approved: null },
    { vaId: 'maria-santos', day: daysAgo(1), hours: 8, note: 'EOD report + travel booking + CRM updates', approved: null },
    { vaId: 'maria-santos', day: daysAgo(2), hours: 7, note: 'Calendar audit, 3 meetings rescheduled', approved: true },
    { vaId: 'maria-santos', day: daysAgo(3), hours: 8, note: 'Inbox zero + CEO brief', approved: true },
    { vaId: 'diana-flores', day: daysAgo(0.3), hours: 5, note: 'Shopify product launches + review ticket queue', approved: null },
    { vaId: 'diana-flores', day: daysAgo(1), hours: 4, note: 'Order fulfilment + supplier emails', approved: true },
    { vaId: 'diana-flores', day: daysAgo(2), hours: 5, note: 'Spike: Black Friday prep', approved: true },
  ],
  // Performance notes per hire (keyed by vaId)
  notes: {
    'maria-santos': [
      { t: daysAgo(1), kind: '30-day', text: 'Hit every KPI in the first month. Calendar load down 30%, inbox at zero. Consider promoting to primary EA for a second exec.' },
      { t: daysAgo(10), kind: 'general', text: 'Great written English, picks up HubSpot workflows fast.' },
    ],
    'diana-flores': [
      { t: daysAgo(5), kind: '60-day', text: 'Solid on daily ops but needs more initiative on supplier escalations. 1:1 coaching in week 10.' },
    ],
  },
  // Stored payment methods, autopay, cap
  billing: {
    methods: [
      { id: 'pm1', brand: 'Visa', last4: '4242', expiry: '09/2028', default: true },
      { id: 'pm2', brand: 'Mastercard', last4: '5151', expiry: '03/2027', default: false },
    ],
    autopay: true,
    autopayAfterDays: 5,
    cap: 3000,
    cycle: 'weekly',
    history: [
      { t: daysAgo(7), amount: 333, method: 'Visa •4242', desc: 'Autopay · INV-2026-0076' },
      { t: daysAgo(7), amount: 200, method: 'Visa •4242', desc: 'Autopay · INV-2026-0087' },
      { t: daysAgo(14), amount: 355.5, method: 'Visa •4242', desc: 'Autopay · INV-2026-0054' },
      { t: daysAgo(14), amount: 200, method: 'Visa •4242', desc: 'Autopay · INV-2026-0065' },
    ],
  },
  // Unified alerts
  notifications: [
    { id: 'n1', kind: 'applicant', title: 'New applicant: Bea Ocampo', body: 'Applied to Executive VA', link: 'applicants?job=exec-assistant', t: daysAgo(0.3), read: false },
    { id: 'n2', kind: 'interview', title: 'Kim Navarro accepted your interview', body: 'Tomorrow 10:00 AM EST · 20 min', link: 'calendar', t: daysAgo(0.4), read: false },
    { id: 'n3', kind: 'timesheet', title: 'Maria Santos submitted today\'s hours', body: '7.5 hrs · Awaiting approval', link: 'timesheets', t: daysAgo(0.5), read: false },
    { id: 'n4', kind: 'invoice', title: 'Invoice INV-2026-0098 flagged', body: 'Diana Flores · 26 hrs (contract is 20h/week)', link: 'invoices', t: daysAgo(1), read: false },
    { id: 'n5', kind: 'trial', title: 'Grace Villanueva finished day 2 of trial', body: 'Real Estate Cold Caller · 150 leads called', link: 'dashboard-client#trials', t: daysAgo(1.4), read: true },
    { id: 'n6', kind: 'invoice', title: 'Autopay released $333.00', body: 'INV-2026-0076 · Visa •4242', link: 'billing', t: daysAgo(7), read: true },
  ],
  // Company settings / verification
  profile: {
    company: 'Carter Digital Agency',
    industry: 'Marketing Agency',
    size: '11–50',
    country: 'United States',
    timezone: 'America/New_York',
    website: 'https://carterdigital.co',
    about: 'Growth marketing agency serving B2B SaaS companies. We hire 2–4 PH VAs each quarter for EA, SDR and content ops.',
    logo: '',
    businessVerified: true,
    paymentVerified: true,
  },
  // Multi-seat
  members: [
    { email: 'james@carterdigital.co', name: 'James Carter', role: 'admin', status: 'active', lastActive: daysAgo(0.1) },
    { email: 'laura@carterdigital.co', name: 'Laura Reyes', role: 'recruiter', status: 'active', lastActive: daysAgo(0.8) },
    { email: 'finance@carterdigital.co', name: 'Finance Team', role: 'billing', status: 'invited', lastActive: null },
  ],
});

/* ---------- Admin queues ---------- */
const seedAdmin = () => ({
  flagged: [
    { id: 'f1', title: 'Data Entry Clerk: Earn $35/hr, Start Today!', client: 'Unverified client', trust: 12, reasons: ['Asks applicants to pay a "registration fee"', 'Moves the conversation to Telegram', 'Promises $35/hr for entry-level data entry'], excerpt: 'No experience needed!! Pay ₱1,500 registration fee via GCash to reserve your slot, then message our HR on Telegram @hr_global_jobs.', reports: 7, status: 'open', date: daysAgo(0.2) },
    { id: 'f2', title: 'Shopify Store Manager (Remote)', client: 'Prime Retail Ventures', trust: 38, reasons: ['Asks applicants to buy a laptop from the client'], excerpt: 'Selected candidates must purchase our company laptop (₱18,000, deducted from first salary) to access our systems.', reports: 3, status: 'open', date: daysAgo(0.6) },
    { id: 'f3', title: 'Bookkeeper for Crypto Fund', client: 'Atlas Capital', trust: 55, reasons: ['Mentions crypto or investments'], excerpt: 'Bookkeeping for our USDT trading fund. Must reconcile wallet transactions weekly in Xero.', reports: 0, status: 'open', date: daysAgo(1) },
  ],
  verifications: [
    { id: 'v1', type: 'ID', name: 'Lyka Ramos', img: 29, detail: 'PhilSys National ID · selfie match 98%', status: 'pending', date: daysAgo(0.1) },
    { id: 'v2', type: 'Brownout-ready', name: 'Paolo Garcia', img: 53, detail: '62 ↓ / 21 ↑ Mbps · 18 ms · Generator · Smart LTE modem', status: 'pending', date: daysAgo(0.4) },
    { id: 'v3', type: 'Business', name: 'Bloom & Co. (Sophie Anderson)', img: 49, detail: 'UK Companies House no. 13845521 · matches billing name', status: 'pending', date: daysAgo(0.7) },
    { id: 'v4', type: 'Certificate', name: 'Mark Tolentino', img: 68, detail: 'Shopify Store Ops · score 88% · proctor flagged 1 tab switch', status: 'pending', date: daysAgo(1.1) },
  ],
  disputes: [
    { id: 'd1', client: 'ShopEase Global', va: 'Jomar Lim', amount: 420, reason: 'Client says the landing page was not delivered as agreed. VA says scope changed twice.', evidence: '28h tracked · 3 scope changes in messages · 1 revision delivered', status: 'open', date: daysAgo(2) },
  ],
  log: [],
});

/* ---------- Helpers used by several pages ---------- */
const vaById = id => (typeof VAS !== 'undefined' && VAS.find(v => v.id === id)) || { id, name: id, img: 1, title: 'Virtual Assistant', rate: 0, rating: 0, reviews: 0, certs: [], brownout: false };
const trustLevel = s => s >= 85 ? 'high' : s >= 60 ? 'mid' : 'low';
const money = n => '$' + Number(n).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
