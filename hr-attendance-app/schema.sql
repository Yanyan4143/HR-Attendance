-- Create the punches table
CREATE TABLE IF NOT EXISTS public.punches (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    state TEXT NOT NULL,
    status TEXT DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'VOIDED')),
    is_manual_edit BOOLEAN DEFAULT FALSE,
    edit_reason TEXT,
    void_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Performance Indexes
CREATE INDEX IF NOT EXISTS idx_punches_timestamp ON public.punches (timestamp);
CREATE INDEX IF NOT EXISTS idx_punches_user_id ON public.punches (user_id);