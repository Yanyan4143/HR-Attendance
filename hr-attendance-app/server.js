require('dotenv').config();

const express = require('express');
const http = require('http');
const path = require('path');
const multer = require('multer');
const { Server } = require('socket.io');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL) {
    throw new Error('Missing SUPABASE_URL in .env');
}

if (!SUPABASE_ANON_KEY) {
    throw new Error('Missing SUPABASE_ANON_KEY in .env');
}

if (!SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error('Missing SUPABASE_SERVICE_ROLE_KEY in .env');
}

const supabasePublic = createClient(
    SUPABASE_URL,
    SUPABASE_ANON_KEY,
    {
        auth: {
            autoRefreshToken: false,
            persistSession: false
        }
    }
);

const supabaseAdmin = createClient(
    SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY,
    {
        auth: {
            autoRefreshToken: false,
            persistSession: false
        }
    }
);

/* =========================================================
   APP CONFIG
========================================================= */

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 10 * 1024 * 1024
    }
});

/* =========================================================
   BASIC HEALTH CHECK
========================================================= */

app.get('/api/health', async (req, res) => {
    res.json({
        ok: true,
        service: 'Tikix HR Attendance',
        time: new Date().toISOString()
    });
});

/* =========================================================
   AUTHENTICATION
========================================================= */

async function authenticateToken(req, res, next) {
    try {
        const authHeader = req.headers.authorization || '';

        if (!authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                error: 'Authentication required.'
            });
        }

        const token = authHeader.substring(7).trim();

        if (!token) {
            return res.status(401).json({
                error: 'Authentication token is missing.'
            });
        }

        const {
            data,
            error
        } = await supabasePublic.auth.getUser(token);

        if (error || !data?.user) {
            return res.status(401).json({
                error: 'Your session has expired. Please sign in again.'
            });
        }

        req.user = data.user;
        req.accessToken = token;

        next();

    } catch (error) {
        console.error('[AUTH MIDDLEWARE]', error);

        return res.status(401).json({
            error: 'Unable to verify your session.'
        });
    }
}

/* =========================================================
   AUDIT LOGGING
========================================================= */

async function recordAuditEvent({
    req = null,
    actor = null,
    eventType,
    employeeId = null,
    punchId = null,
    description = '',
    metadata = {}
}) {
    try {
        const currentActor = actor || req?.user || {};

        const payload = {
            event_type: eventType,
            actor_id: currentActor.id || null,
            actor_email: currentActor.email || null,
            employee_id: employeeId || null,
            punch_id:
                punchId !== null && punchId !== undefined
                    ? String(punchId)
                    : null,
            description,
            metadata: metadata || {}
        };

        const { error } = await supabaseAdmin
            .from('audit_events')
            .insert([payload]);

        if (error) {
            console.error('[AUDIT]', error.message);
        }

    } catch (error) {
        console.error('[AUDIT EXCEPTION]', error.message);
    }
}

/* =========================================================
   AUTH - REGISTER
========================================================= */

app.post('/api/auth/register', async (req, res) => {
    try {
        const {
            fullName,
            companyName,
            email,
            password
        } = req.body || {};

        if (!fullName || !companyName || !email || !password) {
            return res.status(400).json({
                error: 'Full name, company, email and password are required.'
            });
        }

        if (String(password).length < 6) {
            return res.status(400).json({
                error: 'Password must contain at least 6 characters.'
            });
        }

        const cleanEmail = String(email)
            .trim()
            .toLowerCase();

        const {
            data,
            error
        } = await supabaseAdmin.auth.admin.createUser({
            email: cleanEmail,
            password: String(password),
            email_confirm: true,
            user_metadata: {
                fullName: String(fullName).trim(),
                companyName: String(companyName).trim(),
                role: 'hr_admin'
            }
        });

        if (error) {
            console.error('[REGISTER]', error);

            return res.status(400).json({
                error: error.message
            });
        }

        if (!data?.user) {
            return res.status(500).json({
                error: 'Administrator account could not be created.'
            });
        }

        await recordAuditEvent({
            actor: data.user,
            eventType: 'ADMIN_REGISTERED',
            description: `Administrator account created for ${cleanEmail}.`,
            metadata: {
                companyName: String(companyName).trim()
            }
        });

        return res.status(201).json({
            message:
                'Administrator account created successfully. You can now sign in.',
            user: {
                id: data.user.id,
                email: data.user.email
            }
        });

    } catch (error) {
        console.error('[REGISTER EXCEPTION]', error);

        return res.status(500).json({
            error: 'Registration service failed.',
            details: error.message
        });
    }
});

/* =========================================================
   AUTH - LOGIN
========================================================= */

app.post('/api/auth/login', async (req, res) => {
    try {
        const {
            email,
            password
        } = req.body || {};

        if (!email || !password) {
            return res.status(400).json({
                error: 'Email and password are required.'
            });
        }

        const cleanEmail = String(email)
            .trim()
            .toLowerCase();

        console.log(`[AUTH] Login attempt: ${cleanEmail}`);

        const {
            data,
            error
        } = await supabasePublic.auth.signInWithPassword({
            email: cleanEmail,
            password: String(password)
        });

        if (error) {
            console.error(
                `[AUTH] Login failed for ${cleanEmail}:`,
                error.message
            );

            return res.status(401).json({
                error: error.message
            });
        }

        if (!data?.session || !data?.user) {
            return res.status(401).json({
                error: 'Authentication succeeded but no session was created.'
            });
        }

        console.log(`[AUTH] Login successful: ${cleanEmail}`);

        await recordAuditEvent({
            actor: data.user,
            eventType: 'LOGIN',
            description: `Administrator ${cleanEmail} signed in.`,
            metadata: {
                login_method: 'password'
            }
        });

        return res.status(200).json({
            token: data.session.access_token,

            user: {
                id: data.user.id,
                email: data.user.email,

                fullName:
                    data.user.user_metadata?.fullName ||
                    data.user.user_metadata?.full_name ||
                    '',

                companyName:
                    data.user.user_metadata?.companyName ||
                    data.user.user_metadata?.company_name ||
                    '',

                role:
                    data.user.user_metadata?.role ||
                    'hr_admin'
            }
        });

    } catch (error) {
        console.error('[LOGIN EXCEPTION]', error);

        return res.status(500).json({
            error: 'Tikix authentication service failed.',
            details: error.message
        });
    }
});

/* =========================================================
   AUTH - FORGOT PASSWORD
========================================================= */

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body || {};

        if (!email) {
            return res.status(400).json({
                error: 'Email address is required.'
            });
        }

        const cleanEmail = String(email)
            .trim()
            .toLowerCase();

        const origin =
            process.env.APP_URL ||
            `${req.protocol}://${req.get('host')}`;

        const redirectTo =
            `${origin}/reset-password.html`;

        const { error } =
            await supabasePublic.auth.resetPasswordForEmail(
                cleanEmail,
                {
                    redirectTo
                }
            );

        if (error) {
            console.error('[PASSWORD RESET]', error);

            return res.status(400).json({
                error: error.message
            });
        }

        return res.json({
            message:
                'If this email is registered, password recovery instructions have been sent.'
        });

    } catch (error) {
        console.error('[PASSWORD RESET EXCEPTION]', error);

        return res.status(500).json({
            error: 'Unable to process password recovery.'
        });
    }
});

/* =========================================================
   AUTH - LOGOUT
========================================================= */

app.post(
    '/api/auth/logout',
    authenticateToken,
    async (req, res) => {
        try {
            await recordAuditEvent({
                req,
                eventType: 'LOGOUT',
                description:
                    `Administrator ${req.user.email || 'unknown'} signed out.`
            });

            res.json({
                message: 'Signed out successfully.'
            });

        } catch (error) {
            res.json({
                message: 'Signed out.'
            });
        }
    }
);

/* =========================================================
   DATE HELPERS
========================================================= */

function getDateRange(dateString) {
    const date =
        /^\d{4}-\d{2}-\d{2}$/.test(dateString)
            ? dateString
            : new Date().toISOString().slice(0, 10);

    const start = `${date}T00:00:00.000Z`;
    const end = `${date}T23:59:59.999Z`;

    return {
        date,
        start,
        end
    };
}

function minutesBetween(start, end) {
    if (!start || !end) return 0;

    const a = new Date(start).getTime();
    const b = new Date(end).getTime();

    if (!Number.isFinite(a) || !Number.isFinite(b)) {
        return 0;
    }

    return Math.max(0, Math.round((b - a) / 60000));
}

function formatHours(minutes) {
    return (minutes / 60).toFixed(2);
}

function getLocalMinutes(timestamp) {
    const d = new Date(timestamp);

    if (Number.isNaN(d.getTime())) {
        return null;
    }

    return d.getHours() * 60 + d.getMinutes();
}

/* =========================================================
   PUNCH STATE LOGIC
========================================================= */

function calculateEmployee(logs) {
    const validLogs = logs
        .filter(log => String(log.status).toUpperCase() !== 'VOIDED')
        .sort(
            (a, b) =>
                new Date(a.timestamp) -
                new Date(b.timestamp)
        );

    if (!validLogs.length) {
        return null;
    }

    const timeInLog =
        validLogs.find(
            log =>
                String(log.state).toLowerCase() ===
                'time-in'
        ) || null;

    const timeOutLogs =
        validLogs.filter(
            log =>
                String(log.state).toLowerCase() ===
                'time-out'
        );

    const timeOutLog =
        timeOutLogs.length
            ? timeOutLogs[timeOutLogs.length - 1]
            : null;

    const latestLog =
        validLogs[validLogs.length - 1];

    const latestState =
        String(latestLog.state || '').toLowerCase();

    let currentState = 'OFF DUTY';
    let isActive = false;

    if (
        latestState === 'time-in' ||
        latestState === 'break-in' ||
        latestState === 'overtime-in'
    ) {
        isActive = true;
        currentState = 'ON DUTY';
    }

    if (latestState === 'break-out') {
        isActive = true;
        currentState = 'ON BREAK';
    }

    if (
        latestState === 'time-out' ||
        latestState === 'overtime-out'
    ) {
        isActive = false;
        currentState = 'OFF DUTY';
    }

    let breakMinutes = 0;
    let breakOut = null;

    for (const log of validLogs) {
        const state =
            String(log.state || '').toLowerCase();

        if (state === 'break-out') {
            breakOut = log;
        }

        if (
            state === 'break-in' &&
            breakOut
        ) {
            breakMinutes += minutesBetween(
                breakOut.timestamp,
                log.timestamp
            );

            breakOut = null;
        }
    }

    let workedMinutes = 0;

    if (timeInLog) {
        const endTimestamp =
            timeOutLog?.timestamp ||
            new Date().toISOString();

        workedMinutes =
            minutesBetween(
                timeInLog.timestamp,
                endTimestamp
            );

        workedMinutes =
            Math.max(
                0,
                workedMinutes - breakMinutes
            );
    }

    const overtimeMinutes =
        Math.max(
            0,
            workedMinutes - 8 * 60
        );

    const arrivalMinutes =
        timeInLog
            ? getLocalMinutes(timeInLog.timestamp)
            : null;

    const scheduledStartMinutes = 9 * 60;

    const minutesLate =
        arrivalMinutes !== null
            ? Math.max(
                0,
                arrivalMinutes -
                    scheduledStartMinutes
            )
            : 0;

    const isLate =
        minutesLate > 0;

    const manual =
        validLogs.some(
            log => Boolean(log.is_manual)
        );

    return {
        userId: logs[0].user_id,

        timeIn: timeInLog
            ? new Date(
                timeInLog.timestamp
            ).toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit'
            })
            : null,

        timeOut: timeOutLog
            ? new Date(
                timeOutLog.timestamp
            ).toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit'
            })
            : null,

        breakMinutes,

        netWorkHours:
            formatHours(workedMinutes),

        overtimeHours:
            formatHours(overtimeMinutes),

        overtimeMinutes,

        isLate,

        minutesLate,

        status:
            latestLog.state || 'Unknown',

        currentState,

        isActive,

        isEdited: manual,

        punchCount:
            validLogs.length,

        lastActivity:
            latestLog.timestamp,

        rawLogs: validLogs
    };
}

/* =========================================================
   HR ANALYTICS
========================================================= */

app.get(
    '/api/hr-analytics',
    authenticateToken,
    async (req, res) => {
        try {
            const {
                date,
                start,
                end
            } = getDateRange(req.query.date);

            const {
                data: logs,
                error
            } = await supabaseAdmin
                .from('punch_logs')
                .select('*')
                .gte(
                    'timestamp',
                    start
                )
                .lte(
                    'timestamp',
                    end
                )
                .order(
                    'timestamp',
                    {
                        ascending: true
                    }
                );

            if (error) {
                console.error(
                    '[ANALYTICS]',
                    error
                );

                return res.status(500).json({
                    error:
                        'Unable to load attendance data.',
                    details:
                        error.message
                });
            }

            const allLogs =
                Array.isArray(logs)
                    ? logs
                    : [];

            const validLogs =
                allLogs.filter(
                    log =>
                        String(
                            log.status
                        ).toUpperCase() !==
                        'VOIDED'
                );

            const voidedLogs =
                allLogs.filter(
                    log =>
                        String(
                            log.status
                        ).toUpperCase() ===
                        'VOIDED'
                );

            const employeeMap = new Map();

            for (const log of validLogs) {
                if (!employeeMap.has(log.user_id)) {
                    employeeMap.set(
                        log.user_id,
                        []
                    );
                }

                employeeMap
                    .get(log.user_id)
                    .push(log);
            }

            const employees = [];

            for (const [
                userId,
                employeeLogs
            ] of employeeMap.entries()) {
                const employee =
                    calculateEmployee(
                        employeeLogs
                    );

                if (employee) {
                    employees.push(
                        employee
                    );
                }
            }

            const activeEmployees =
                employees.filter(
                    employee =>
                        employee.isActive
                );

            const lateEmployees =
                employees.filter(
                    employee =>
                        employee.isLate
                );

            const overtimeEmployees =
                employees.filter(
                    employee =>
                        Number(
                            employee.overtimeHours
                        ) > 0
                );

            const totalWorkedMinutes =
                employees.reduce(
                    (sum, employee) =>
                        sum +
                        Math.round(
                            Number(
                                employee.netWorkHours
                            ) * 60
                        ),
                    0
                );

            const averageWorkHours =
                employees.length
                    ? (
                        totalWorkedMinutes /
                        60 /
                        employees.length
                    ).toFixed(2)
                    : '0.00';

            const totalOTMinutes =
                employees.reduce(
                    (sum, employee) =>
                        sum +
                        Number(
                            employee.overtimeMinutes ||
                            0
                        ),
                    0
                );

            const punctualityRate =
                employees.length
                    ? Math.round(
                        (
                            (
                                employees.length -
                                lateEmployees.length
                            ) /
                            employees.length
                        ) * 100
                    )
                    : 100;

            return res.json({
                date,

                stats: {
                    totalHeadcount:
                        employees.length,

                    currentlyActive:
                        activeEmployees.length,

                    lateArrivals:
                        lateEmployees.length,

                    overtimeWorkers:
                        overtimeEmployees.length,

                    punctualityRate,

                    totalOTAccumulated:
                        formatHours(
                            totalOTMinutes
                        ),

                    averageWorkHours
                },

                employees,

                voidedLogs
            });

        } catch (error) {
            console.error(
                '[ANALYTICS EXCEPTION]',
                error
            );

            return res.status(500).json({
                error:
                    'Attendance analytics failed.',
                details:
                    error.message
            });
        }
    }
);

/* =========================================================
   ATTENDANCE HISTORY
========================================================= */

app.get(
    '/api/hr-history',
    authenticateToken,
    async (req, res) => {
        try {
            const employee =
                String(
                    req.query.employee || ''
                ).trim();

            const from =
                /^\d{4}-\d{2}-\d{2}$/.test(
                    req.query.from || ''
                )
                    ? req.query.from
                    : new Date(
                        Date.now() -
                        30 * 86400000
                    )
                        .toISOString()
                        .slice(0, 10);

            const to =
                /^\d{4}-\d{2}-\d{2}$/.test(
                    req.query.to || ''
                )
                    ? req.query.to
                    : new Date()
                        .toISOString()
                        .slice(0, 10);

            let query =
                supabaseAdmin
                    .from('punch_logs')
                    .select('*')
                    .gte(
                        'timestamp',
                        `${from}T00:00:00.000Z`
                    )
                    .lte(
                        'timestamp',
                        `${to}T23:59:59.999Z`
                    )
                    .order(
                        'timestamp',
                        {
                            ascending: false
                        }
                    )
                    .limit(5000);

            if (employee) {
                query =
                    query.eq(
                        'user_id',
                        employee
                    );
            }

            const {
                data,
                error
            } = await query;

            if (error) {
                return res.status(500).json({
                    error:
                        'Unable to load attendance history.',
                    details:
                        error.message
                });
            }

            res.json({
                from,
                to,
                records: data || []
            });

        } catch (error) {
            res.status(500).json({
                error:
                    'Attendance history failed.',
                details:
                    error.message
            });
        }
    }
);

/* =========================================================
   SYSTEM ACTIVITY
========================================================= */

app.get(
    '/api/system-activity',
    authenticateToken,
    async (req, res) => {
        try {
            const limit = Math.min(
                Math.max(
                    Number(req.query.limit) || 100,
                    1
                ),
                500
            );

            let query =
                supabaseAdmin
                    .from('audit_events')
                    .select('*')
                    .order(
                        'created_at',
                        {
                            ascending: false
                        }
                    )
                    .limit(limit);

            if (req.query.type) {
                query =
                    query.eq(
                        'event_type',
                        String(
                            req.query.type
                        )
                    );
            }

            const {
                data,
                error
            } = await query;

            if (error) {
                return res.status(500).json({
                    error:
                        'Unable to load system activity.',
                    details:
                        error.message
                });
            }

            res.json({
                events: data || []
            });

        } catch (error) {
            res.status(500).json({
                error:
                    'System activity failed.',
                details:
                    error.message
            });
        }
    }
);

/* =========================================================
   MANUAL PUNCH
========================================================= */

app.post(
    '/api/punch/manual',
    authenticateToken,
    async (req, res) => {
        try {
            const {
                userId,
                date,
                time,
                state,
                reason
            } = req.body || {};

            if (
                !userId ||
                !date ||
                !time ||
                !state ||
                !reason
            ) {
                return res.status(400).json({
                    error:
                        'Employee ID, date, time, state and reason are required.'
                });
            }

            if (
                !/^\d{4}-\d{2}-\d{2}$/.test(
                    date
                )
            ) {
                return res.status(400).json({
                    error:
                        'Invalid date format.'
                });
            }

            if (
                !/^\d{2}:\d{2}$/.test(
                    time
                )
            ) {
                return res.status(400).json({
                    error:
                        'Invalid time format.'
                });
            }

            const timestamp =
                `${date}T${time}:00.000Z`;

            const {
                data,
                error
            } = await supabaseAdmin
                .from('punch_logs')
                .insert([
                    {
                        user_id:
                            String(userId).trim(),
                        timestamp,
                        state:
                            String(state).trim(),
                        status: 'VALID',
                        is_manual: true,
                        override_reason:
                            String(reason).trim()
                    }
                ])
                .select()
                .single();

            if (error) {
                console.error(
                    '[MANUAL PUNCH]',
                    error
                );

                return res.status(500).json({
                    error:
                        'Unable to create manual punch.',
                    details:
                        error.message
                });
            }

            await recordAuditEvent({
                req,
                eventType:
                    'MANUAL_OVERRIDE',
                employeeId:
                    String(userId).trim(),
                punchId:
                    data.id,
                description:
                    `Manual ${state} recorded for ${userId}.`,
                metadata: {
                    timestamp,
                    state,
                    reason:
                        String(
                            reason
                        ).trim()
                }
            });

            io.emit('dataRefreshed');

            res.status(201).json({
                message:
                    'Manual attendance record saved.',
                record: data
            });

        } catch (error) {
            console.error(
                '[MANUAL PUNCH EXCEPTION]',
                error
            );

            res.status(500).json({
                error:
                    'Manual override failed.',
                details:
                    error.message
            });
        }
    }
);

/* =========================================================
   VOID PUNCH
========================================================= */

app.post(
    '/api/punch/void',
    authenticateToken,
    async (req, res) => {
        try {
            const {
                id,
                reason
            } = req.body || {};

            if (
                id === undefined ||
                id === null ||
                !reason
            ) {
                return res.status(400).json({
                    error:
                        'Punch ID and audit reason are required.'
                });
            }

            const {
                data: original,
                error:
                    fetchError
            } = await supabaseAdmin
                .from('punch_logs')
                .select('*')
                .eq('id', id)
                .single();

            if (fetchError) {
                return res.status(404).json({
                    error:
                        'Attendance record not found.'
                });
            }

            if (
                String(
                    original.status
                ).toUpperCase() ===
                'VOIDED'
            ) {
                return res.status(400).json({
                    error:
                        'This attendance record has already been voided.'
                });
            }

            const {
                data: updated,
                error
            } = await supabaseAdmin
                .from('punch_logs')
                .update({
                    status: 'VOIDED',
                    void_reason:
                        String(reason).trim(),
                    voided_at:
                        new Date().toISOString(),
                    voided_by:
                        req.user.id
                })
                .eq('id', id)
                .select()
                .single();

            if (error) {
                return res.status(500).json({
                    error:
                        'Unable to void attendance record.',
                    details:
                        error.message
                });
            }

            await recordAuditEvent({
                req,
                eventType:
                    'VOID_PUNCH',
                employeeId:
                    original.user_id,
                punchId:
                    original.id,
                description:
                    `Punch ${original.id} for ${original.user_id} was voided.`,
                metadata: {
                    original_state:
                        original.state,
                    original_timestamp:
                        original.timestamp,
                    reason:
                        String(
                            reason
                        ).trim()
                }
            });

            io.emit('dataRefreshed');

            res.json({
                message:
                    'Attendance record voided successfully.',
                record: updated
            });

        } catch (error) {
            console.error(
                '[VOID PUNCH]',
                error
            );

            res.status(500).json({
                error:
                    'Unable to void attendance record.',
                details:
                    error.message
            });
        }
    }
);

/* =========================================================
   USB IMPORT
========================================================= */

app.post(
    '/api/upload-usb',
    authenticateToken,
    upload.single('logfile'),
    async (req, res) => {
        try {
            if (!req.file) {
                return res.status(400).json({
                    error:
                        'Please select a CSV, DAT or TXT attendance file.'
                });
            }

            /*
             * IMPORTANT:
             * multer uses memoryStorage(), therefore
             * req.file.path DOES NOT EXIST.
             *
             * We correctly read req.file.buffer.
             */

            const content =
                req.file.buffer.toString(
                    'utf8'
                );

            const lines =
                content
                    .split(/\r?\n/)
                    .map(
                        line =>
                            line.trim()
                    )
                    .filter(Boolean);

            const records = [];

            for (const line of lines) {
                const parts =
                    line
                        .split(
                            /\t|,|;/
                        )
                        .map(
                            value =>
                                value
                                    .trim()
                                    .replace(
                                        /^["']|["']$/g,
                                        ''
                                    )
                        );

                if (parts.length < 3) {
                    continue;
                }

                const userId =
                    parts[0];

                const timestamp =
                    parts[1];

                const state =
                    parts[2];

                if (
                    !userId ||
                    !timestamp ||
                    !state
                ) {
                    continue;
                }

                const parsedDate =
                    new Date(timestamp);

                if (
                    Number.isNaN(
                        parsedDate.getTime()
                    )
                ) {
                    continue;
                }

                records.push({
                    user_id: userId,
                    timestamp:
                        parsedDate.toISOString(),
                    state,
                    status: 'VALID',
                    is_manual: false
                });
            }

            if (!records.length) {
                return res.status(400).json({
                    error:
                        'No valid attendance records were found in the imported file.'
                });
            }

            const {
                data,
                error
            } = await supabaseAdmin
                .from('punch_logs')
                .insert(records)
                .select();

            if (error) {
                console.error(
                    '[USB IMPORT]',
                    error
                );

                return res.status(500).json({
                    error:
                        'Unable to import USB attendance records.',
                    details:
                        error.message
                });
            }

            await recordAuditEvent({
                req,
                eventType:
                    'USB_IMPORT',
                description:
                    `Imported ${records.length} attendance records from ${req.file.originalname}.`,
                metadata: {
                    filename:
                        req.file.originalname,
                    recordsImported:
                        records.length
                }
            });

            io.emit('dataRefreshed');

            res.status(201).json({
                message:
                    `${records.length} attendance record(s) imported successfully.`,
                count:
                    records.length,
                records:
                    data || []
            });

        } catch (error) {
            console.error(
                '[USB IMPORT EXCEPTION]',
                error
            );

            res.status(500).json({
                error:
                    'USB import failed.',
                details:
                    error.message
            });
        }
    }
);

/* =========================================================
   BIOMETRIC PUSH
========================================================= */

app.post(
    '/api/biometric/push',
    async (req, res) => {
        try {
            const {
                userId,
                timestamp,
                state
            } = req.body || {};

            if (
                !userId ||
                !timestamp ||
                !state
            ) {
                return res.status(400).json({
                    error:
                        'userId, timestamp and state are required.'
                });
            }

            const parsedDate =
                new Date(timestamp);

            if (
                Number.isNaN(
                    parsedDate.getTime()
                )
            ) {
                return res.status(400).json({
                    error:
                        'Invalid timestamp.'
                });
            }

            const {
                data,
                error
            } = await supabaseAdmin
                .from('punch_logs')
                .insert([
                    {
                        user_id:
                            String(
                                userId
                            ).trim(),
                        timestamp:
                            parsedDate.toISOString(),
                        state:
                            String(
                                state
                            ).trim(),
                        status: 'VALID',
                        is_manual: false
                    }
                ])
                .select()
                .single();

            if (error) {
                return res.status(500).json({
                    error:
                        'Unable to save biometric punch.',
                    details:
                        error.message
                });
            }

            await recordAuditEvent({
                eventType:
                    'BIOMETRIC_SYNC',
                employeeId:
                    String(
                        userId
                    ).trim(),
                punchId:
                    data.id,
                description:
                    `Biometric punch received for ${userId}.`,
                metadata: {
                    state,
                    timestamp:
                        parsedDate.toISOString()
                }
            });

            io.emit('dataRefreshed');

            res.status(201).json({
                message:
                    'Biometric punch recorded.',
                record: data
            });

        } catch (error) {
            console.error(
                '[BIOMETRIC]',
                error
            );

            res.status(500).json({
                error:
                    'Biometric synchronization failed.',
                details:
                    error.message
            });
        }
    }
);

/* =========================================================
   SOCKET.IO
========================================================= */

io.on('connection', socket => {
    console.log(
        `[SOCKET] Client connected: ${socket.id}`
    );

    socket.on('disconnect', () => {
        console.log(
            `[SOCKET] Client disconnected: ${socket.id}`
        );
    });
});

/* =========================================================
   SPA FALLBACK
========================================================= */

app.get('*', (req, res, next) => {
    if (
        req.path.startsWith('/api/')
    ) {
        return next();
    }

    res.sendFile(
        path.join(
            __dirname,
            'public',
            'index.html'
        )
    );
});

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
    (err, req, res, next) => {
        console.error(
            '[SERVER ERROR]',
            err
        );

        res.status(500).json({
            error:
                'Internal server error.',
            details:
                err.message
        });
    }
);

/* =========================================================
   START SERVER
========================================================= */

server.listen(
    PORT,
    () => {
        console.log('');
        console.log(
            '======================================'
        );
        console.log(
            ' Tikix HR Attendance'
        );
        console.log(
            ' Server running on port ' +
                PORT
        );
        console.log(
            '======================================'
        );
        console.log('');
    }
);
