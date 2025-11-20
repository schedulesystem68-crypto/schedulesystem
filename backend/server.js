require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();

// ===== Middleware =====
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ===== MongoDB Connection =====
mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/schedule_system', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(()=>console.log('✅ MongoDB connected'))
.catch(err=>console.error('❌ MongoDB connection error:', err));

const { Schema, model } = mongoose;
const JWT_SECRET = process.env.JWT_SECRET || 'secretkey';

// ===== Schemas =====
// User
const userSchema = new Schema({
  userId: { type: String, unique: true },
  name: { type: String, required: true },
  username: { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['admin','user','client'], default: 'user' },
  clientsCount: { type: Number, default: 0 }
});
userSchema.methods.verifyPass = function(pw){ return bcrypt.compareSync(pw, this.passwordHash); };
const User = model('User', userSchema);

// Client
const clientSchema = new Schema({
  name: { type: String, required: true },
  createdBy: { type: String },
  createdAt: { type: Date, default: Date.now }
});
const Client = model('Client', clientSchema);

// Assignment
const assignmentSchema = new Schema({
  clientId: { type: Schema.Types.ObjectId, ref: 'Client', default: null },
  clientName: { type: String, required: true },
  userId: { type: String, required: true },
  month: { type: String, required: true },
  weekdays: [{ type: Number }],
  weeklyTotals: {
    posters: { type: Number, default: 0 },
    reels: { type: Number, default: 0 }
  },
  startDate: Date,
  createdBy: String,
  createdAt: { type: Date, default: Date.now },
  calendar: {
    type: Map,
    of: [{ day: Number, poster: Boolean, reel: Boolean, completed: Boolean }],
    default: {}
  }
});
const Assignment = model('Assignment', assignmentSchema);

// Task
const taskSchema = new Schema({
  assignmentId: { type: Schema.Types.ObjectId, ref: 'Assignment' },
  userId: { type: String },
  clientId: { type: Schema.Types.ObjectId, ref: 'Client' },
  clientName: { type: String },
  date: { type: Date },
  type: { type: String, enum: ['poster','reel'] },
  count: { type: Number, default: 1 },
  notes: String,
  createdAt: { type: Date, default: Date.now }
});
const Task = model('Task', taskSchema);

// ===== Auth Middleware =====
function authMiddleware(req,res,next){
  const header = req.headers['authorization'];
  if(!header) return res.status(401).json({ error: 'No auth token' });
  const parts = header.split(' ');
  if(parts.length!==2) return res.status(401).json({ error: 'Invalid auth header' });
  const token = parts[1];
  try{
    const data = jwt.verify(token, JWT_SECRET);
    req.user = data;
    next();
  }catch(e){
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ===== Root Route (NEW) =====
app.get('/', (req, res) => {
  res.send('🚀 Schedule System Backend is running!');
});

// ===== Register =====
app.post('/api/register', async (req,res)=>{
  try{
    const { name, username, password, role } = req.body;
    if(!name || !username || !password || !role)
      return res.status(400).json({ error: 'All fields required' });

    const existing = await User.findOne({ username });
    if(existing) return res.status(400).json({ error: 'Username already exists' });

    const count = await User.countDocuments();
    const userId = 'U' + String(count + 1).padStart(3, '0');
    const passwordHash = bcrypt.hashSync(password, 10);

    const user = new User({ userId, name, username, passwordHash, role });
    await user.save();

    const token = jwt.sign(
      { userId: user.userId, username: user.username, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ success: true, token, user: { userId: user.userId, username: user.username, role: user.role, name: user.name } });
  }catch(err){
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== Login =====
app.post('/api/login', async (req,res)=>{
  try{
    const { username, password } = req.body;
    if(!username || !password)
      return res.status(400).json({ error: 'All fields required' });

    const user = await User.findOne({ username });
    if(!user) return res.status(400).json({ error: 'Invalid username or password' });

    const valid = user.verifyPass(password);
    if(!valid) return res.status(400).json({ error: 'Invalid username or password' });

    const token = jwt.sign(
      { userId: user.userId, username: user.username, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ success: true, token, user: { userId: user.userId, username: user.username, role: user.role, name: user.name } });
  }catch(err){
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== Verify Token =====
app.get('/api/verify', authMiddleware, (req, res) => {
  res.json({ success: true, user: req.user });
});

// ===== Admin Get All Users =====
app.get('/api/users', authMiddleware, async (req,res)=>{
  try{
    if(req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const users = await User.find({}, 'userId name username role clientsCount').lean();
    res.json({ success: true, users });
  }catch(err){
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== Clients listing =====
app.get('/api/clients', authMiddleware, async (req,res)=>{
  try{
    if(req.user.role === 'admin'){
      const assignments = await Assignment.find().lean();
      const users = await User.find({}, 'userId name').lean();
      const userMap = {};
      users.forEach(u=>{ userMap[u.userId] = u.name });

      const map = {};
      for(const a of assignments){
        if(!map[a.clientName]) map[a.clientName] = { name: a.clientName, assignments: [] };
        map[a.clientName].assignments.push({
          ...a,
          assignedTo: userMap[a.userId] || 'Unassigned'
        });
      }

      const clients = [];
      for(const key of Object.keys(map)){
        const group = map[key];
        const first = group.assignments[0] || {};
        const weekly = group.assignments.reduce((acc, it)=>{
          acc.posters += (it.weeklyTotals && it.weeklyTotals.posters) ? it.weeklyTotals.posters : 0;
          acc.reels += (it.weeklyTotals && it.weeklyTotals.reels) ? it.weeklyTotals.reels : 0;
          return acc;
        }, { posters: 0, reels: 0 });
        clients.push({
          name: key,
          assignedCount: group.assignments.length,
          sample: first,
          weeklyTotals: weekly,
          assignments: group.assignments
        });
      }
      return res.json({ success: true, clients });
    } else {
      const assigns = await Assignment.find({ userId: req.user.userId }).lean();
      const clients = assigns.map(a=>({
        name: a.clientName,
        assignmentId: a._id,
        month: a.month,
        weekdays: a.weekdays,
        weeklyTotals: a.weeklyTotals || { posters: 0, reels: 0 },
        startDate: a.startDate,
        assignedTo: req.user.name,
        calendar: a.calendar || {}
      }));
      return res.json({ success: true, clients });
    }
  }catch(err){ console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// ===== Create Assignment (Admin) =====
app.post('/api/assignments', authMiddleware, async (req,res)=>{
  try{
    if(req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });

    const { clientName, weeklyTotals, assignedUser, startDate } = req.body;
    if(!clientName || !assignedUser) return res.status(400).json({ error: 'Missing client or user' });

    let client = await Client.findOne({ name: clientName });
    if(!client){
      client = new Client({ name: clientName, createdBy: req.user.userId });
      await client.save();
    }

    const month = new Date().toISOString().slice(0,7);
    const weekdays = [1,2,3,4,5,6,7];

    const assignment = new Assignment({
      clientId: client._id,
      clientName,
      userId: assignedUser,
      month,
      weekdays,
      weeklyTotals: weeklyTotals && typeof weeklyTotals === 'object' ? {
        posters: Number(weeklyTotals.posters || 0),
        reels: Number(weeklyTotals.reels || 0)
      } : { posters: 0, reels: 0 },
      startDate: startDate ? new Date(startDate) : null,
      createdBy: req.user.userId
    });

    await assignment.save();
    await User.findOneAndUpdate({ userId: assignedUser }, { $inc: { clientsCount: 1 } });

    res.json({ success: true, assignment });
  }catch(err){
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== Get calendar for an assignment (month) =====
app.get('/api/assignments/:id/calendar', authMiddleware, async (req, res) => {
  try {
    const assignmentId = req.params.id;
    const month = req.query.month;
    if (!assignmentId) return res.status(400).json({ error: 'Assignment id required' });
    if (!month) return res.status(400).json({ error: 'Month is required (YYYY-MM)' });

    const assignment = await Assignment.findById(assignmentId).lean();
    if (!assignment) return res.status(404).json({ error: 'Assignment not found' });

    if (req.user.role !== 'admin' && req.user.userId !== assignment.userId) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    let days = [];
    if (assignment.calendar && (assignment.calendar instanceof Map)) {
      days = assignment.calendar.get(month) || [];
    } else if (assignment.calendar && typeof assignment.calendar === 'object') {
      days = assignment.calendar[month] || [];
    }

    return res.json({ success: true, days });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== Save calendar for an assignment (month) =====
app.post('/api/assignments/:id/save-calendar', authMiddleware, async (req, res) => {
  try {
    const assignmentId = req.params.id;
    const { month, days } = req.body;

    if (!assignmentId) return res.status(400).json({ error: 'Assignment id required' });
    if (!month || !Array.isArray(days)) return res.status(400).json({ error: 'Month and days are required' });

    const assignment = await Assignment.findById(assignmentId);
    if (!assignment) return res.status(404).json({ error: 'Assignment not found' });

    if (req.user.role !== 'admin' && req.user.userId !== assignment.userId) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    if (assignment.calendar instanceof Map) {
      assignment.calendar.set(month, days);
    } else {
      const obj = assignment.calendar || {};
      obj[month] = days;
      assignment.calendar = obj;
    }

    await assignment.save();
    return res.json({ success: true, message: 'Calendar saved' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== Delete Client (Admin) =====
app.delete('/api/clients/:clientName', authMiddleware, async (req,res)=>{
  try{
    if(req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const { clientName } = req.params;
    if(!clientName) return res.status(400).json({ error: 'Client name required' });

    const assignments = await Assignment.find({ clientName });
    if(assignments.length === 0) return res.status(404).json({ error: 'Client not found' });

    for(const a of assignments){
      await Task.deleteMany({ assignmentId: a._id });
      await a.deleteOne();
      await User.findOneAndUpdate({ userId: a.userId }, { $inc: { clientsCount: -1 } });
    }

    res.json({ success: true, message: 'Client and related assignments deleted' });
  }catch(err){ console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// ===== Start Server =====
const PORT = process.env.PORT || 4000;
app.listen(PORT, ()=>console.log(`🚀 Server running on port ${PORT}`));
