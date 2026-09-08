const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { createClient } = require('@supabase/supabase-js');
const multer = require('multer');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;

const SUPABASE_URL =
    process.env.SUPABASE_URL ||
    'https://YOUR_PROJECT_REF.supabase.co';

const SUPABASE_ANON_KEY =
    process.env.SUPABASE_ANON_KEY ||
    'YOUR_SUPABASE_ANON_KEY';

const SUPABASE_SERVICE_ROLE_KEY =
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    'YOUR_SERVICE_ROLE_KEY';

const supabasePublic = createClient(
    SUPABASE_URL,
    SUPABASE_ANON_KEY
);

const supabaseAdmin = createClient(
    SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
    express.static(
        path.join(__dirname, 'public')
    )
);

/*
|--------------------------------------------------------------------------
| FILE UPLOAD
|--------------------------------------------------------------------------
*/

const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 10 * 1024 * 1024
    }
});

/*
|--------------------------------------------------------------------------
| AUTHENTICATION
|--------------------------------------------------------------------------
*/

async function authenticateToken(req, res, next) {
    try {
        const authHeader = req.headers.authorization;

        const token =
            authHeader &&
            authHeader.startsWith('Bearer ')
                ? authHeader.split(' ')[1]
                : null;

        if (!token) {
            return res.status(401).json({
                error: 'Access token required.'
            });
        }

        const {
            data: { user },
            error
        } = await supabasePublic.auth.getUser(token);

        if (error || !user) {
            return res.status(401).json({
                error: 'Invalid or expired session.'
            });
        }

        req.user = user;
        next();

    } catch (error) {
        console.error('Authentication error:', error);

        return res.status(401).json({
            error: 'Authentication failed.'
        });
    }
}

/*
|--------------------------------------------------------------------------
| AUDIT LOGGER
|--------------------------------------------------------------------------
*/

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
        const currentActor =
            actor ||
            (req && req.user) ||
            {};

        const { error } = await supabaseAdmin
            .from('audit_events')
            .insert([
                {
                    event_type: eventType,
                    actor_id: currentActor.id || null,
                    actor_email: currentActor.email || null,
                    employee_id:
                        employeeId !== null
                            ? String(employeeId)
                            : null,
                    punch_id:
                        punchId !== null
                            ? String(punchId)
                            : null,
                    description,
                    metadata
                }
            ]);

        if (error) {
            console.error(
                'Audit insert error:',
                error
            );
        }

    } catch (error) {
        console.error(
            'Audit logger exception:',
            error
        );
    }
}

/*
|--------------------------------------------------------------------------
| UTILITY FUNCTIONS
|--------------------------------------------------------------------------
*/

function round(value, decimals = 2) {
    const multiplier =
        Math.pow(10, decimals);

    return (
        Math.round(
            (Number(value) || 0) *
            multiplier
        ) / multiplier
    );
}

function formatDateOnly(date) {
    return date
        .toISOString()
        .split('T')[0];
}

function getDateRange(dateString) {
    const start = new Date(
        `${dateString}T00:00:00.000Z`
    );

    const end = new Date(
        `${dateString}T23:59:59.999Z`
    );

    return {
        start: start.toISOString(),
        end: end.toISOString()
    };
}

function timeToMinutes(value) {
    if (!value) return null;

    const match =
        String(value).match(
            /(\d{1,2}):(\d{2})/
        );

    if (!match) return null;

    return (
        Number(match[1]) * 60 +
        Number(match[2])
    );
}

function timestampToTime(timestamp) {
    if (!timestamp) return '--';

    return new Date(timestamp)
        .toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit'
        });
}

function timestampToDate(timestamp) {
    if (!timestamp) return '--';

    return new Date(timestamp)
        .toLocaleDateString([], {
            year: 'numeric',
            month: 'short',
            day: '2-digit'
        });
}

/*
|--------------------------------------------------------------------------
| AUTH - REGISTER
|--------------------------------------------------------------------------
*/

app.post(
    '/api/auth/register',
    async (req, res) => {
        try {
            const {
                fullName,
                companyName,
                email,
                password
            } = req.body;

            if (
                !fullName ||
                !companyName ||
                !email ||
                !password
            ) {
                return res.status(400).json({
                    error:
                        'All registration fields are required.'
                });
            }

            if (password.length < 6) {
                return res.status(400).json({
                    error:
                        'Password must be at least 6 characters.'
                });
            }

            const {
                data,
                error
            } =
                await supabaseAdmin.auth.admin.createUser(
                    {
                        email,
                        password,
                        email_confirm: true,
                        user_metadata: {
                            full_name: fullName,
                            company_name: companyName,
                            role: 'hr_admin'
                        }
                    }
                );

            if (error) {
                return res.status(400).json({
                    error: error.message
                });
            }

            await recordAuditEvent({
                actor: data.user,
                eventType:
                    'ADMIN_REGISTERED',
                description:
                    `Administrator account created for ${email}.`,
                metadata: {
                    companyName
                }
            });

            return res.json({
                message:
                    'Administrator account created successfully.'
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                error:
                    'Unable to create administrator account.'
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| AUTH - LOGIN
|--------------------------------------------------------------------------
*/

app.post(
    '/api/auth/login',
    async (req, res) => {
        try {
            const {
                email,
                password
            } = req.body;

            if (!email || !password) {
                return res.status(400).json({
                    error:
                        'Email and password are required.'
                });
            }

            const {
                data,
                error
            } =
                await supabasePublic.auth.signInWithPassword(
                    {
                        email,
                        password
                    }
                );

            if (
                error ||
                !data.session ||
                !data.user
            ) {
                return res.status(401).json({
                    error:
                        error?.message ||
                        'Invalid login credentials.'
                });
            }

            await recordAuditEvent({
                actor: data.user,
                eventType: 'LOGIN',
                description:
                    `Administrator ${email} signed in.`,
                metadata: {
                    loginMethod:
                        'password'
                }
            });

            return res.json({
                token:
                    data.session.access_token,

                user: {
                    id: data.user.id,
                    email: data.user.email,
                    fullName:
                        data.user.user_metadata
                            ?.full_name ||
                        '',
                    companyName:
                        data.user.user_metadata
                            ?.company_name ||
                        '',
                    role:
                        data.user.user_metadata
                            ?.role ||
                        'hr_admin'
                }
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                error:
                    'Authentication service unavailable.'
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| AUTH - LOGOUT
|--------------------------------------------------------------------------
*/

app.post(
    '/api/auth/logout',
    authenticateToken,
    async (req, res) => {
        await recordAuditEvent({
            req,
            eventType: 'LOGOUT',
            description:
                `Administrator ${req.user.email} signed out.`,
            metadata: {}
        });

        res.json({
            message: 'Logout recorded.'
        });
    }
);

/*
|--------------------------------------------------------------------------
| AUTH - PASSWORD RESET
|--------------------------------------------------------------------------
*/

app.post(
    '/api/auth/forgot-password',
    async (req, res) => {
        try {
            const { email } = req.body;

            if (!email) {
                return res.status(400).json({
                    error:
                        'Email address is required.'
                });
            }

            const {
                error
            } =
                await supabasePublic.auth.resetPasswordForEmail(
                    email
                );

            if (error) {
                return res.status(400).json({
                    error: error.message
                });
            }

            return res.json({
                message:
                    'Password recovery instructions have been sent.'
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                error:
                    'Unable to process password recovery.'
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| HR ANALYTICS
|--------------------------------------------------------------------------
*/

app.get(
    '/api/hr-analytics',
    authenticateToken,
    async (req, res) => {
        try {
            const selectedDate =
                req.query.date ||
                formatDateOnly(new Date());

            const {
                start,
                end
            } =
                getDateRange(
                    selectedDate
                );

            const {
                data: logs,
                error
            } =
                await supabaseAdmin
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
                throw error;
            }

            const validLogs =
                (logs || []).filter(
                    log =>
                        String(
                            log.status ||
                            'VALID'
                        ).toUpperCase() !==
                        'VOIDED'
                );

            const voidedLogs =
                (logs || []).filter(
                    log =>
                        String(
                            log.status ||
                            ''
                        ).toUpperCase() ===
                        'VOIDED'
                );

            /*
            -------------------------------------------------------
            GROUP LOGS BY EMPLOYEE
            -------------------------------------------------------
            */

            const grouped = {};

            validLogs.forEach(log => {
                const id =
                    String(log.user_id);

                if (!grouped[id]) {
                    grouped[id] = [];
                }

                grouped[id].push(log);
            });

            const now = new Date();

            const employees =
                Object.entries(
                    grouped
                ).map(
                    ([userId, employeeLogs]) => {

                        employeeLogs.sort(
                            (a, b) =>
                                new Date(a.timestamp) -
                                new Date(b.timestamp)
                        );

                        const firstTimeIn =
                            employeeLogs.find(
                                log =>
                                    log.state ===
                                    'Time-In'
                            );

                        const timeOutLogs =
                            employeeLogs.filter(
                                log =>
                                    log.state ===
                                    'Time-Out'
                            );

                        const lastTimeOut =
                            timeOutLogs.length
                                ? timeOutLogs[
                                      timeOutLogs.length -
                                          1
                                  ]
                                : null;

                        const lastLog =
                            employeeLogs[
                                employeeLogs.length -
                                    1
                            ];

                        /*
                        ------------------------------------------------
                        CURRENT STATE
                        ------------------------------------------------
                        */

                        let currentState =
                            'OFF DUTY';

                        if (
                            lastLog.state ===
                                'Time-In' ||
                            lastLog.state ===
                                'Break-In' ||
                            lastLog.state ===
                                'Overtime-In'
                        ) {
                            currentState =
                                'ON DUTY';
                        }

                        if (
                            lastLog.state ===
                            'Break-Out'
                        ) {
                            currentState =
                                'ON BREAK';
                        }

                        if (
                            lastLog.state ===
                                'Time-Out' ||
                            lastLog.state ===
                                'Overtime-Out'
                        ) {
                            currentState =
                                'OFF DUTY';
                        }

                        const isActive =
                            currentState ===
                                'ON DUTY' ||
                            currentState ===
                                'ON BREAK';

                        /*
                        ------------------------------------------------
                        LATE CALCULATION
                        ------------------------------------------------
                        */

                        let minutesLate = 0;

                        if (firstTimeIn) {
                            const d =
                                new Date(
                                    firstTimeIn.timestamp
                                );

                            const actualMinutes =
                                d.getHours() *
                                    60 +
                                d.getMinutes();

                            const scheduledMinutes =
                                9 * 60;

                            if (
                                actualMinutes >
                                scheduledMinutes
                            ) {
                                minutesLate =
                                    actualMinutes -
                                    scheduledMinutes;
                            }
                        }

                        /*
                        ------------------------------------------------
                        BREAK CALCULATION
                        ------------------------------------------------
                        */

                        let breakMinutes = 0;
                        let openBreak = null;

                        employeeLogs.forEach(
                            log => {
                                if (
                                    log.state ===
                                    'Break-Out'
                                ) {
                                    openBreak =
                                        new Date(
                                            log.timestamp
                                        );
                                }

                                if (
                                    log.state ===
                                        'Break-In' &&
                                    openBreak
                                ) {
                                    const breakEnd =
                                        new Date(
                                            log.timestamp
                                        );

                                    const diff =
                                        (
                                            breakEnd -
                                            openBreak
                                        ) /
                                        60000;

                                    if (
                                        diff > 0 &&
                                        diff < 1440
                                    ) {
                                        breakMinutes +=
                                            diff;
                                    }

                                    openBreak = null;
                                }
                            }
                        );

                        /*
                        ------------------------------------------------
                        WORK HOURS
                        ------------------------------------------------
                        */

                        let endTime =
                            lastTimeOut
                                ? new Date(
                                      lastTimeOut.timestamp
                                  )
                                : isActive
                                ? now
                                : null;

                        let netWorkHours = 0;

                        if (
                            firstTimeIn &&
                            endTime
                        ) {
                            const startTime =
                                new Date(
                                    firstTimeIn.timestamp
                                );

                            const elapsedHours =
                                (
                                    endTime -
                                    startTime
                                ) /
                                3600000;

                            netWorkHours =
                                Math.max(
                                    0,
                                    elapsedHours -
                                        breakMinutes /
                                            60
                                );
                        }

                        netWorkHours =
                            round(
                                netWorkHours
                            );

                        /*
                        ------------------------------------------------
                        OVERTIME
                        ------------------------------------------------
                        */

                        const overtimeHours =
                            round(
                                Math.max(
                                    0,
                                    netWorkHours -
                                        8
                                )
                            );

                        /*
                        ------------------------------------------------
                        MANUAL EDIT
                        ------------------------------------------------
                        */

                        const isEdited =
                            employeeLogs.some(
                                log =>
                                    log.is_manual ===
                                    true
                            );

                        /*
                        ------------------------------------------------
                        DATA SOURCE
                        ------------------------------------------------
                        */

                        let dataSource =
                            'Biometric Terminal';

                        if (isEdited) {
                            dataSource =
                                'Manual Override';
                        } else if (
                            employeeLogs.some(
                                log =>
                                    log.source ===
                                    'USB'
                            )
                        ) {
                            dataSource =
                                'USB Import';
                        }

                        return {
                            userId,

                            timeIn:
                                firstTimeIn
                                    ? timestampToTime(
                                          firstTimeIn.timestamp
                                      )
                                    : '--',

                            timeOut:
                                lastTimeOut
                                    ? timestampToTime(
                                          lastTimeOut.timestamp
                                      )
                                    : '--',

                            breakMinutes:
                                Math.round(
                                    breakMinutes
                                ),

                            netWorkHours,

                            overtimeHours,

                            minutesLate,

                            isLate:
                                minutesLate > 0,

                            status:
                                currentState,

                            currentState,

                            isActive,

                            isEdited,

                            dataSource,

                            punchCount:
                                employeeLogs.length,

                            lastActivity:
                                lastLog
                                    ? lastLog.timestamp
                                    : null,

                            rawLogs:
                                employeeLogs
                        };
                    }
                );

            /*
            -------------------------------------------------------
            STATS
            -------------------------------------------------------
            */

            const totalHeadcount =
                employees.length;

            const currentlyActive =
                employees.filter(
                    e => e.isActive
                ).length;

            const lateArrivals =
                employees.filter(
                    e => e.isLate
                ).length;

            const overtimeWorkers =
                employees.filter(
                    e =>
                        Number(
                            e.overtimeHours
                        ) > 0
                ).length;

            const totalOT =
                employees.reduce(
                    (sum, e) =>
                        sum +
                        Number(
                            e.overtimeHours ||
                                0
                        ),
                    0
                );

            const workedEmployees =
                employees.filter(
                    e =>
                        Number(
                            e.netWorkHours
                        ) > 0
                );

            const averageWorkHours =
                workedEmployees.length
                    ? workedEmployees.reduce(
                          (sum, e) =>
                              sum +
                              Number(
                                  e.netWorkHours
                              ),
                          0
                      ) /
                      workedEmployees.length
                    : 0;

            const punctualityRate =
                totalHeadcount
                    ? (
                          (
                              totalHeadcount -
                              lateArrivals
                          ) /
                          totalHeadcount
                      ) *
                      100
                    : 100;

            /*
            -------------------------------------------------------
            ACTIVITY FOR SELECTED DAY
            -------------------------------------------------------
            */

            const {
                data: activity
            } =
                await supabaseAdmin
                    .from('audit_events')
                    .select('*')
                    .gte(
                        'created_at',
                        start
                    )
                    .lte(
                        'created_at',
                        end
                    )
                    .order(
                        'created_at',
                        {
                            ascending: false
                        }
                    )
                    .limit(100);

            res.json({
                selectedDate,

                stats: {
                    totalHeadcount,
                    currentlyActive,
                    lateArrivals,
                    punctualityRate:
                        round(
                            punctualityRate,
                            1
                        ),
                    totalOTAccumulated:
                        round(totalOT),
                    overtimeWorkers,
                    averageWorkHours:
                        round(
                            averageWorkHours
                        )
                },

                employees,

                voidedLogs,

                activity:
                    activity || []
            });

        } catch (error) {
            console.error(
                'HR analytics error:',
                error
            );

            res.status(500).json({
                error:
                    'Unable to load HR analytics.'
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| ATTENDANCE HISTORY
|--------------------------------------------------------------------------
*/

app.get(
    '/api/hr-history',
    authenticateToken,
    async (req, res) => {
        try {
            const from =
                req.query.from ||
                formatDateOnly(
                    new Date(
                        Date.now() -
                            30 *
                                86400000
                    )
                );

            const to =
                req.query.to ||
                formatDateOnly(
                    new Date()
                );

            const employee =
                req.query.employee ||
                '';

            const {
                start
            } =
                getDateRange(from);

            const {
                end
            } =
                getDateRange(to);

            let query =
                supabaseAdmin
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
                throw error;
            }

            res.json({
                from,
                to,
                records:
                    data || []
            });

        } catch (error) {
            console.error(
                'History error:',
                error
            );

            res.status(500).json({
                error:
                    'Unable to load attendance history.'
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| SYSTEM ACTIVITY
|--------------------------------------------------------------------------
*/

app.get(
    '/api/system-activity',
    authenticateToken,
    async (req, res) => {
        try {
            const limit = Math.min(
                Number(
                    req.query.limit || 200
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
                        req.query.type
                    );
            }

            const {
                data,
                error
            } = await query;

            if (error) {
                throw error;
            }

            res.json({
                activity:
                    data || []
            });

        } catch (error) {
            console.error(
                'Activity error:',
                error
            );

            res.status(500).json({
                error:
                    'Unable to load system activity.'
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| MANUAL PUNCH
|--------------------------------------------------------------------------
*/

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
            } = req.body;

            if (
                !userId ||
                !date ||
                !time ||
                !state ||
                !reason
            ) {
                return res.status(400).json({
                    error:
                        'Employee, date, time, state and reason are required.'
                });
            }

            const timestamp =
                `${date}T${time}:00Z`;

            const {
                data,
                error
            } =
                await supabaseAdmin
                    .from('punch_logs')
                    .insert([
                        {
                            user_id: userId,
                            timestamp,
                            state,
                            status: 'VALID',
                            is_manual: true,
                            override_reason:
                                reason,
                            source: 'MANUAL'
                        }
                    ])
                    .select()
                    .single();

            if (error) {
                throw error;
            }

            await recordAuditEvent({
                req,
                eventType:
                    'MANUAL_OVERRIDE',
                employeeId: userId,
                punchId: data?.id,
                description:
                    `Manual ${state} punch created for ${userId}.`,
                metadata: {
                    state,
                    timestamp,
                    reason
                }
            });

            io.emit(
                'dataRefreshed'
            );

            res.json({
                message:
                    'Manual attendance record created successfully.',
                record: data
            });

        } catch (error) {
            console.error(
                'Manual punch error:',
                error
            );

            res.status(500).json({
                error:
                    'Unable to create manual punch.'
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| VOID PUNCH
|--------------------------------------------------------------------------
*/

app.post(
    '/api/punch/void',
    authenticateToken,
    async (req, res) => {
        try {
            const {
                id,
                reason
            } = req.body;

            if (!id || !reason) {
                return res.status(400).json({
                    error:
                        'Punch ID and void reason are required.'
                });
            }

            const {
                data: original,
                error: fetchError
            } =
                await supabaseAdmin
                    .from('punch_logs')
                    .select('*')
                    .eq('id', id)
                    .single();

            if (fetchError) {
                throw fetchError;
            }

            if (
                String(
                    original.status ||
                        ''
                ).toUpperCase() ===
                'VOIDED'
            ) {
                return res.status(400).json({
                    error:
                        'This punch has already been voided.'
                });
            }

            const now =
                new Date().toISOString();

            const {
                data,
                error
            } =
                await supabaseAdmin
                    .from('punch_logs')
                    .update({
                        status: 'VOIDED',
                        void_reason:
                            reason,
                        voided_at: now,
                        voided_by:
                            req.user.id
                    })
                    .eq('id', id)
                    .select()
                    .single();

            if (error) {
                throw error;
            }

            await recordAuditEvent({
                req,
                eventType:
                    'VOID_PUNCH',
                employeeId:
                    original.user_id,
                punchId: original.id,
                description:
                    `Punch ${original.state} for ${original.user_id} was voided.`,
                metadata: {
                    originalTimestamp:
                        original.timestamp,
                    originalState:
                        original.state,
                    originalStatus:
                        original.status,
                    voidReason:
                        reason,
                    voidedAt: now
                }
            });

            io.emit(
                'dataRefreshed'
            );

            res.json({
                message:
                    'Punch record voided successfully.',
                record: data
            });

        } catch (error) {
            console.error(
                'Void punch error:',
                error
            );

            res.status(500).json({
                error:
                    'Unable to void punch record.'
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| USB / TERMINAL IMPORT
|--------------------------------------------------------------------------
*/

app.post(
    '/api/upload-usb',
    authenticateToken,
    upload.single('logfile'),
    async (req, res) => {
        try {
            if (!req.file) {
                return res.status(400).json({
                    error:
                        'No attendance file was uploaded.'
                });
            }

            /*
            IMPORTANT:
            multer uses memoryStorage(),
            therefore req.file.path DOES NOT EXIST.
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
                            /[\t,;]+/
                        )
                        .map(
                            value =>
                                value.trim()
                        );

                if (
                    parts.length < 3
                ) {
                    continue;
                }

                const [
                    userId,
                    timestamp,
                    state
                ] = parts;

                if (
                    !userId ||
                    !timestamp ||
                    !state
                ) {
                    continue;
                }

                records.push({
                    user_id: userId,
                    timestamp:
                        new Date(
                            timestamp
                        ).toISOString(),
                    state,
                    status: 'VALID',
                    is_manual: false,
                    source: 'USB'
                });
            }

            if (!records.length) {
                return res.status(400).json({
                    error:
                        'No valid attendance records were found in the file.'
                });
            }

            const {
                data,
                error
            } =
                await supabaseAdmin
                    .from('punch_logs')
                    .insert(
                        records
                    )
                    .select();

            if (error) {
                throw error;
            }

            await recordAuditEvent({
                req,
                eventType:
                    'USB_IMPORT',
                description:
                    `USB attendance import completed: ${records.length} records.`,
                metadata: {
                    filename:
                        req.file.originalname,
                    recordCount:
                        records.length
                }
            });

            io.emit(
                'dataRefreshed'
            );

            res.json({
                message:
                    `USB import completed. ${records.length} attendance records imported.`,
                count:
                    records.length,
                records:
                    data || []
            });

        } catch (error) {
            console.error(
                'USB import error:',
                error
            );

            res.status(500).json({
                error:
                    'USB attendance import failed.'
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| BIOMETRIC PUSH
|--------------------------------------------------------------------------
*/

app.post(
    '/api/biometric/push',
    async (req, res) => {
        try {
            const {
                userId,
                timestamp,
                state
            } = req.body;

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

            const {
                data,
                error
            } =
                await supabaseAdmin
                    .from('punch_logs')
                    .insert([
                        {
                            user_id:
                                userId,
                            timestamp:
                                new Date(
                                    timestamp
                                ).toISOString(),
                            state,
                            status:
                                'VALID',
                            is_manual:
                                false,
                            source:
                                'BIOMETRIC'
                        }
                    ])
                    .select()
                    .single();

            if (error) {
                throw error;
            }

            await recordAuditEvent({
                eventType:
                    'BIOMETRIC_SYNC',
                employeeId:
                    userId,
                punchId:
                    data?.id,
                description:
                    `Biometric ${state} punch received for ${userId}.`,
                metadata: {
                    timestamp:
                        data.timestamp,
                    state
                }
            });

            io.emit(
                'dataRefreshed'
            );

            res.json({
                message:
                    'Biometric punch accepted.',
                record: data
            });

        } catch (error) {
            console.error(
                'Biometric error:',
                error
            );

            res.status(500).json({
                error:
                    'Unable to process biometric punch.'
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| SOCKET.IO
|--------------------------------------------------------------------------
*/

io.on(
    'connection',
    socket => {
        console.log(
            `Tikix HR client connected: ${socket.id}`
        );

        socket.on(
            'disconnect',
            () => {
                console.log(
                    `Tikix HR client disconnected: ${socket.id}`
                );
            }
        );
    }
);

/*
|--------------------------------------------------------------------------
| ROOT
|--------------------------------------------------------------------------
*/

app.get(
    '/',
    (req, res) => {
        res.sendFile(
            path.join(
                __dirname,
                'public',
                'index.html'
            )
        );
    }
);

/*
|--------------------------------------------------------------------------
| START
|--------------------------------------------------------------------------
*/

server.listen(
    PORT,
    () => {
        console.log(
            `Tikix HR Attendance running on port ${PORT}`
        );
    }
);
