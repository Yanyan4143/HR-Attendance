require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: '*' } });

const upload = multer({ dest: 'uploads/' });

// Initialize Supabase Client
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Express Middlewares
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.text({ type: '*/*' })); // Parses raw ADMS hardware telemetry
app.use(express.static(path.join(__dirname, 'public')));

const SHIFT_START_HOUR = parseInt(process.env.SHIFT_START_HOUR || '8');
const SHIFT_START_MINUTE = parseInt(process.env.SHIFT_START_MINUTE || '0');

// JWT Token Authentication Middleware
async function authenticateHR(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized: Missing token' });
    }

    const token = authHeader.split(' ')[1];
    const { data: { user }, error } = await supabase.auth.getUser(token);

    if (error || !user) {
        return res.status(401).json({ error: 'Unauthorized: Invalid or expired session' });
    }

    req.user = user;
    next();
}

// -------------------------------------------------------------
// AUTHENTICATION ENDPOINTS
// -------------------------------------------------------------

// HR Login
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) return res.status(400).json({ error: error.message });

    res.json({
        message: 'Login successful',
        token: data.session.access_token,
        user: data.user
    });
});

// Admin Account Registration
app.post('/api/auth/register', async (req, res) => {
    const { email, password, fullName, companyName } = req.body;
    if (!email || !password || !fullName) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    const { data, error } = await supabase.auth.signUp({
        email,
        password,
        options: { data: { full_name: fullName, company_name: companyName } }
    });

    if (error) return res.status(400).json({ error: error.message });
    res.json({ message: 'Admin account created successfully. You may now sign in.' });
});

// Password Recovery Request
app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email address is required.' });

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
        redirectTo: `${req.protocol}://${req.get('host')}/`
    });

    if (error) return res.status(400).json({ error: error.message });
    res.json({ message: 'Password recovery instructions sent to your email.' });
});

// -------------------------------------------------------------
// ADMS HARDWARE DIRECT PUSH ENDPOINTS (NGTeco Protocol)
// -------------------------------------------------------------

app.get('/iclock/cdata.aspx', (req, res) => res.send('OK'));

app.post('/iclock/cdata.aspx', async (req, res) => {
    const rawData = req.body;

    if (typeof rawData === 'string') {
        const lines = rawData.split('\n');
        const rowsToInsert = [];

        lines.forEach(line => {
            const parts = line.split('\t');
            if (parts.length >= 2) {
                const userId = parts[0].trim();
                const timestamp = parts[1].trim();
                const stateCode = parts[2] ? parts[2].trim() : '0';

                const stateMap = {
                    '0': 'Time-In',
                    '1': 'Time-Out',
                    '2': 'Break-Out',
                    '3': 'Break-In',
                    '4': 'Overtime-In',
                    '5': 'Overtime-Out'
                };

                rowsToInsert.push({
                    user_id: userId,
                    timestamp: new Date(timestamp).toISOString(),
                    state: stateMap[stateCode] || 'Time-In',
                    status: 'ACTIVE',
                    is_manual_edit: false
                });
            }
        });

        if (rowsToInsert.length > 0) {
            const { error } = await supabase.from('punches').insert(rowsToInsert);
            if (error) {
                console.error('Supabase ADMS Insert Error:', error);
            } else {
                io.emit('dataRefreshed');
            }
        }
    }

    res.send('OK');
});

app.get('/iclock/getrequest.aspx', (req, res) => res.send('OK'));

// -------------------------------------------------------------
// TIMECARD CALCULATIONS ENGINE
// -------------------------------------------------------------
function calculateShiftData(employeeId, logs, selectedDateStr) {
    let timeIn = null, timeOut = null, breakOut = null, breakIn = null, otIn = null, otOut = null;
    let isEdited = logs.some(l => l.is_manual_edit);

    logs.forEach(log => {
        const state = log.state.toUpperCase().replace(/\s+/g, '-');
        const logTime = new Date(log.timestamp);

        if (state === 'TIME-IN' && !timeIn) timeIn = logTime;
        else if (state === 'BREAK-OUT') breakOut = logTime;
        else if (state === 'BREAK-IN') breakIn = logTime;
        else if (state === 'OVERTIME-IN') otIn = logTime;
        else if (state === 'OVERTIME-OUT') otOut = logTime;
        else if (state === 'TIME-OUT') timeOut = logTime;
    });

    let workHours = 0, breakMins = 0, otHours = 0, isLate = false;

    if (timeIn) {
        const expectedStart = new Date(timeIn);
        expectedStart.setHours(SHIFT_START_HOUR, SHIFT_START_MINUTE, 0, 0);
        if (timeIn > expectedStart) isLate = true;
    }

    if (timeIn && timeOut) workHours = (timeOut - timeIn) / (1000 * 60 * 60);
    if (breakOut && breakIn) {
        breakMins = (breakIn - breakOut) / (1000 * 60);
        workHours -= (breakMins / 60);
    }
    if (otIn && otOut) otHours = (otOut - otIn) / (1000 * 60 * 60);

    const lastLog = logs[logs.length - 1];

    return {
        userId: employeeId,
        date: selectedDateStr,
        timeIn: timeIn ? timeIn.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '--',
        timeOut: timeOut ? timeOut.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '--',
        breakMinutes: breakMins.toFixed(0),
        netWorkHours: Math.max(0, workHours).toFixed(2),
        overtimeHours: otHours.toFixed(2),
        status: lastLog ? lastLog.state : 'Absent',
        isLate,
        isEdited,
        rawLogs: logs
    };
}

// -------------------------------------------------------------
// PROTECTED HR DASHBOARD ANALYTICS API
// -------------------------------------------------------------
app.get('/api/hr-analytics', authenticateHR, async (req, res) => {
    const targetDate = req.query.date || new Date().toISOString().split('T')[0];
    const startOfDay = `${targetDate}T00:00:00.000Z`;
    const endOfDay = `${targetDate}T23:59:59.999Z`;

    const { data: activeLogs, error: activeErr } = await supabase
        .from('punches')
        .select('*')
        .gte('timestamp', startOfDay)
        .lte('timestamp', endOfDay)
        .eq('status', 'ACTIVE')
        .order('timestamp', { ascending: true });

    const { data: voidedLogs } = await supabase
        .from('punches')
        .select('*')
        .gte('timestamp', startOfDay)
        .lte('timestamp', endOfDay)
        .eq('status', 'VOIDED')
        .order('timestamp', { ascending: true });

    if (activeErr) return res.status(500).json({ error: activeErr.message });

    const uniqueUsers = [...new Set(activeLogs.map(item => item.user_id))];

    const employeeSummaries = uniqueUsers.map(id => {
        const userLogs = activeLogs.filter(l => l.user_id === id);
        return calculateShiftData(id, userLogs, targetDate);
    });

    const totalHeadcount = employeeSummaries.length;
    const currentlyActive = employeeSummaries.filter(e => e.status.toUpperCase() !== 'TIME-OUT').length;
    const lateArrivals = employeeSummaries.filter(e => e.isLate).length;
    const overtimeWorkers = employeeSummaries.filter(e => parseFloat(e.overtimeHours) > 0).length;
    const totalOTAccumulated = employeeSummaries.reduce((sum, e) => sum + parseFloat(e.overtimeHours), 0);
    const totalHoursAccumulated = employeeSummaries.reduce((sum, e) => sum + parseFloat(e.netWorkHours), 0);

    res.json({
        selectedDate: targetDate,
        stats: {
            totalHeadcount,
            currentlyActive,
            lateArrivals,
            overtimeWorkers,
            punctualityRate: totalHeadcount > 0 ? (((totalHeadcount - lateArrivals) / totalHeadcount) * 100).toFixed(0) : 100,
            totalOTAccumulated: totalOTAccumulated.toFixed(1),
            averageWorkHours: totalHeadcount > 0 ? (totalHoursAccumulated / totalHeadcount).toFixed(1) : 0
        },
        employees: employeeSummaries,
        voidedLogs: voidedLogs || []
    });
});

// Manual Punch Override
app.post('/api/punch/manual', authenticateHR, async (req, res) => {
    const { userId, date, time, state, reason } = req.body;

    const { error } = await supabase.from('punches').insert([{
        user_id: userId.trim(),
        timestamp: new Date(`${date}T${time}:00`).toISOString(),
        state: state.trim(),
        status: 'ACTIVE',
        is_manual_edit: true,
        edit_reason: reason || 'HR Override'
    }]);

    if (error) return res.status(400).json({ error: error.message });

    io.emit('dataRefreshed');
    res.json({ status: 'Success', message: 'Manual punch saved.' });
});

// Soft-Void Log
app.post('/api/punch/void', authenticateHR, async (req, res) => {
    const { id, reason } = req.body;

    const { error } = await supabase
        .from('punches')
        .update({ status: 'VOIDED', void_reason: reason || 'Admin Voided' })
        .eq('id', id);

    if (error) return res.status(400).json({ error: error.message });

    io.emit('dataRefreshed');
    res.json({ status: 'Success', message: 'Punch record voided successfully.' });
});

// USB Log Upload
app.post('/api/upload-usb', authenticateHR, upload.single('logfile'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No log file provided.' });

    const content = fs.readFileSync(req.file.path, 'utf-8');
    const rowsToInsert = [];

    content.split('\n').forEach(line => {
        const parts = line.trim().split(',');
        if (parts.length >= 3) {
            rowsToInsert.push({
                user_id: parts[0].trim(),
                timestamp: new Date(parts[1].trim()).toISOString(),
                state: parts[2].trim(),
                status: 'ACTIVE',
                is_manual_edit: false
            });
        }
    });

    fs.unlinkSync(req.file.path);

    if (rowsToInsert.length > 0) {
        const { error } = await supabase.from('punches').insert(rowsToInsert);
        if (error) return res.status(400).json({ error: error.message });
        io.emit('dataRefreshed');
    }

    res.json({ status: 'Success', message: 'USB logs synced to database.' });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`ADMS Server running on http://localhost:${PORT}`));