const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { createClient } = require('@supabase/supabase-js');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;

// Supabase Credentials (replace with environment variables or your keys)
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://YOUR_PROJECT_REF.supabase.co';
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'YOUR_SUPABASE_ANON_KEY';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'YOUR_SERVICE_ROLE_KEY';

// Initialize Supabase Clients
const supabasePublic = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Multer Config for USB Import File Uploads
const upload = multer({ dest: 'uploads/' });

// Middleware: Authenticate Request via Supabase Access Token
async function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access token required.' });

    const { data: { user }, error } = await supabasePublic.auth.getUser(token);

    if (error || !user) {
        return res.status(401).json({ error: 'Invalid or expired session.' });
    }

    req.user = user;
    next();
}

/* ==========================================================================
   1. SUPABASE AUTHENTICATION ROUTES
   ========================================================================== */

// POST /api/auth/register - Create Admin Account via Supabase Auth
app.post('/api/auth/register', async (req, res) => {
    const { fullName, companyName, email, password } = req.body;
    if (!fullName || !companyName || !email || !password) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    // Auto-confirm account using Supabase Service Role Key to bypass email confirmation step
    const { data, error } = await supabaseAdmin.auth.admin.createUser({
        email: email.toLowerCase(),
        password,
        email_confirm: true,
        user_metadata: { fullName, companyName, role: 'admin' }
    });

    if (error) {
        return res.status(400).json({ error: error.message });
    }

    res.status(201).json({ message: 'Administrator account created successfully.' });
});

// POST /api/auth/login - Admin Login via Supabase
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });

    const { data, error } = await supabasePublic.auth.signInWithPassword({
        email: email.toLowerCase(),
        password
    });

    if (error) {
        return res.status(401).json({ error: error.message });
    }

    res.json({
        token: data.session.access_token,
        user: {
            id: data.user.id,
            email: data.user.email,
            fullName: data.user.user_metadata?.fullName,
            company: data.user.user_metadata?.companyName
        }
    });
});

// POST /api/auth/forgot-password - Send Reset Link via Supabase
app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email address required.' });

    const { error } = await supabasePublic.auth.resetPasswordForEmail(email.toLowerCase());

    if (error) {
        return res.status(400).json({ error: error.message });
    }

    res.json({ message: 'Password recovery instructions sent to registered email.' });
});

/* ==========================================================================
   2. TELEMETRY & ANALYTICS ROUTE
   ========================================================================== */

// GET /api/hr-analytics - Fetch processed daily attendance metrics
app.get('/api/hr-analytics', authenticateToken, async (req, res) => {
    const selectedDate = req.query.date || new Date().toISOString().split('T')[0];

    // Query logs for selected date from Supabase
    const { data: rows, error } = await supabaseAdmin
        .from('punch_logs')
        .select('*')
        .gte('timestamp', `${selectedDate}T00:00:00Z`)
        .lte('timestamp', `${selectedDate}T23:59:59Z`)
        .order('timestamp', { ascending: true });

    if (error) {
        return res.status(500).json({ error: 'Failed to fetch attendance telemetry.' });
    }

    const validLogs = (rows || []).filter(log => log.status !== 'VOIDED');
    const voidedLogs = (rows || []).filter(log => log.status === 'VOIDED');

    // Group valid logs by Employee User ID
    const empMap = {};
    validLogs.forEach(log => {
        if (!empMap[log.user_id]) empMap[log.user_id] = [];
        empMap[log.user_id].push(log);
    });

    const employees = [];
    let totalHeadcount = Object.keys(empMap).length;
    let currentlyActive = 0;
    let lateArrivals = 0;
    let totalOTAccumulated = 0;
    let totalWorkedMinutesSum = 0;

    Object.keys(empMap).forEach(userId => {
        const logs = empMap[userId];
        const timeInLog = logs.find(l => l.state === 'Time-In');
        const timeOutLog = [...logs].reverse().find(l => l.state === 'Time-Out');
        const latestLog = logs[logs.length - 1];

        const isActive = latestLog && latestLog.state !== 'Time-Out';
        if (isActive) currentlyActive++;

        const timeIn = timeInLog ? new Date(timeInLog.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '--';
        const timeOut = timeOutLog ? new Date(timeOutLog.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '--';

        let isLate = false;
        if (timeInLog) {
            const inTime = new Date(timeInLog.timestamp);
            if (inTime.getHours() > 9 || (inTime.getHours() === 9 && inTime.getMinutes() > 0)) {
                isLate = true;
                lateArrivals++;
            }
        }

        let netWorkHours = 0;
        let overtimeHours = 0;
        if (timeInLog && timeOutLog) {
            const diffMs = new Date(timeOutLog.timestamp) - new Date(timeInLog.timestamp);
            const totalHours = Math.max(0, diffMs / (1000 * 60 * 60));
            netWorkHours = parseFloat(totalHours.toFixed(2));

            if (netWorkHours > 8) {
                overtimeHours = parseFloat((netWorkHours - 8).toFixed(2));
                totalOTAccumulated += overtimeHours;
            }
            totalWorkedMinutesSum += netWorkHours;
        }

        const isEdited = logs.some(l => l.is_manual);

        employees.push({
            userId,
            timeIn,
            timeOut,
            breakMinutes: 0,
            netWorkHours,
            overtimeHours,
            isLate,
            status: isActive ? 'TIME-IN' : 'TIME-OUT',
            isEdited,
            rawLogs: logs
        });
    });

    const punctualityRate = totalHeadcount > 0 
        ? Math.round(((totalHeadcount - lateArrivals) / totalHeadcount) * 100) 
        : 100;

    const averageWorkHours = totalHeadcount > 0 
        ? (totalWorkedMinutesSum / totalHeadcount).toFixed(1) 
        : 0;

    res.json({
        stats: {
            totalHeadcount,
            currentlyActive,
            lateArrivals,
            punctualityRate,
            totalOTAccumulated: totalOTAccumulated.toFixed(1),
            overtimeWorkers: employees.filter(e => e.overtimeHours > 0).length,
            averageWorkHours
        },
        employees,
        voidedLogs
    });
});

/* ==========================================================================
   3. PUNCH MODIFICATION & MANUAL OVERRIDE API
   ========================================================================== */

// POST /api/punch/manual - Submit Manual Punch Override
app.post('/api/punch/manual', authenticateToken, async (req, res) => {
    const { userId, date, time, state, reason } = req.body;
    if (!userId || !date || !time || !state || !reason) {
        return res.status(400).json({ error: 'Missing required manual punch fields.' });
    }

    const fullTimestamp = `${date}T${time}:00Z`;

    const { error } = await supabaseAdmin.from('punch_logs').insert([
        { user_id: userId, timestamp: fullTimestamp, state, status: 'VALID', is_manual: true, override_reason: reason }
    ]);

    if (error) return res.status(500).json({ error: error.message });

    io.emit('dataRefreshed');
    res.status(201).json({ message: 'Manual override recorded successfully.' });
});

// POST /api/punch/void - Soft-void punch entry
app.post('/api/punch/void', authenticateToken, async (req, res) => {
    const { id, reason } = req.body;
    if (!id || !reason) return res.status(400).json({ error: 'Punch ID and mandatory reason required.' });

    const { error } = await supabaseAdmin
        .from('punch_logs')
        .update({ status: 'VOIDED', void_reason: reason })
        .eq('id', id);

    if (error) return res.status(500).json({ error: error.message });

    io.emit('dataRefreshed');
    res.json({ message: 'Log entry voided successfully.' });
});

// POST /api/upload-usb - Upload raw USB device logs
app.post('/api/upload-usb', authenticateToken, upload.single('logfile'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });

    const filePath = req.file.path;
    fs.readFile(filePath, 'utf8', async (err, data) => {
        if (err) return res.status(500).json({ error: 'Error reading uploaded file.' });

        const lines = data.split('\n');
        const rowsToInsert = [];

        lines.forEach(line => {
            const parts = line.trim().split(/[\t,]+/);
            if (parts.length >= 2) {
                const userId = parts[0];
                const timestamp = parts[1];
                const state = parts[2] || 'Time-In';

                if (userId && timestamp) {
                    rowsToInsert.push({ user_id: userId, timestamp, state, status: 'VALID' });
                }
            }
        });

        if (rowsToInsert.length > 0) {
            await supabaseAdmin.from('punch_logs').insert(rowsToInsert);
        }

        fs.unlinkSync(filePath);
        io.emit('dataRefreshed');
        res.json({ message: `Successfully imported ${rowsToInsert.length} raw records.` });
    });
});

/* ==========================================================================
   4. DEVICE / TERMINAL INGESTION API (NGTeco Webhook)
   ========================================================================== */

app.post('/api/biometric/push', async (req, res) => {
    const { userId, timestamp, state } = req.body;
    if (!userId || !timestamp) return res.status(400).send('BAD_DATA');

    const { error } = await supabaseAdmin.from('punch_logs').insert([
        { user_id: userId, timestamp, state: state || 'Time-In', status: 'VALID' }
    ]);

    if (error) return res.status(500).send('ERROR');

    io.emit('dataRefreshed');
    res.send('OK');
});

// Socket Listener
io.on('connection', (socket) => {
    console.log(`Live Dashboard Client Connected: ${socket.id}`);
});

server.listen(PORT, () => {
    console.log(`Tikix HR Server running on port ${PORT}`);
});
