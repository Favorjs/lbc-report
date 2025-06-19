import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { BrowserRouter as Router, Route, Routes, Navigate, Link, useNavigate } from 'react-router-dom';
import {
  Container, Box, Typography, TextField, Button, Checkbox, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, Paper, Select, MenuItem, InputLabel, FormControl,
  Snackbar, Alert, CircularProgress, AppBar, Toolbar, IconButton, Drawer, List, ListItem,
  ListItemText, Divider, Grid, Dialog, DialogTitle, DialogContent, DialogActions, Chip, Tooltip
} from '@mui/material';
import { 
  Menu as MenuIcon, ExitToApp as ExitToAppIcon, 
  Add as AddIcon, Delete as DeleteIcon, Edit as EditIcon, Refresh as RefreshIcon 
} from '@mui/icons-material';

// Base URL for API
axios.defaults.baseURL = process.env.NODE_ENV === 'production' 
  ? process.env.REACT_APP_API_URL 
  : 'http://localhost:5000';

// CSS Styles
const styles = `
  :root {
    --primary: #4361ee;
    --secondary: #3f37c9;
    --accent: #4895ef;
    --success: #4cc9f0;
    --warning: #f72585;
    --light: #f8f9fa;
    --dark: #212529;
    --gray: #6c757d;
  }

  body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background-color: #f5f7fa;
    color: var(--dark);
  }

  .app-container {
    display: flex;
    min-height: 100vh;
  }

  .main-content {
    flex: 1;
    padding: 20px;
    margin-top: 64px;
  }

  .paper-container {
    border-radius: 12px !important;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08) !important;
    padding: 24px;
    margin-bottom: 24px;
    background-color: white;
  }

  .page-title {
    font-weight: 600 !important;
    margin-bottom: 24px !important;
    color: var(--primary);
  }

  .section-title {
    font-weight: 500 !important;
    margin-bottom: 16px !important;
  }

  .primary-button {
    background-color: var(--primary) !important;
    color: white !important;
    font-weight: 500 !important;
    text-transform: none !important;
    padding: 8px 16px !important;
    border-radius: 8px !important;
    transition: all 0.3s ease;
  }

  .primary-button:hover {
    background-color: var(--secondary) !important;
    transform: translateY(-2px);
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
  }

  .danger-button {
    background-color: var(--warning) !important;
    color: white !important;
  }

  .form-control {
    margin-bottom: 16px !important;
  }

  .data-table {
    border-radius: 8px !important;
    overflow: hidden;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
  }

  .data-table .MuiTableCell-head {
    font-weight: 600 !important;
    background-color: #f8f9fa;
  }

  .data-table .MuiTableCell-body {
    padding: 12px 16px !important;
  }

  .member-row {
    transition: background-color 0.2s;
  }

  .member-row:hover {
    background-color: rgba(67, 97, 238, 0.05);
  }

  .submit-btn {
    min-width: 120px;
    transition: all 0.3s ease;
  }

  .submitted-btn {
    background-color: var(--success) !important;
    color: white !important;
    cursor: default;
  }

  .filter-container {
    display: flex;
    gap: 16px;
    margin-bottom: 24px;
    flex-wrap: wrap;
  }

  .auth-container {
    max-width: 500px;
    margin: 0 auto;
    padding: 24px;
  }

  .auth-title {
    text-align: center;
    margin-bottom: 24px !important;
    color: var(--primary);
  }

  .auth-form {
    margin-top: 16px;
  }

  .auth-link {
    text-align: center;
    margin-top: 16px;
  }

  @media (max-width: 768px) {
    .main-content {
      padding: 16px;
    }
    
    .paper-container {
      padding: 16px;
    }
    
    .filter-container {
      flex-direction: column;
      gap: 12px;
    }
    
    .responsive-table {
      overflow-x: auto;
    }
  }
`;

// Add styles to document head
const styleSheet = document.createElement("style");
styleSheet.textContent = styles;
document.head.appendChild(styleSheet);

// Components
const App = () => {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<AuthWrapper />} />
        <Route path="/login" element={<Login />} />
        <Route path="/admin-login" element={<AdminLogin />} />
        <Route path="/admin-register" element={<AdminRegister />} />
        <Route path="/register" element={<Register />} />
        <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
        <Route path="/admin" element={<ProtectedRoute adminOnly><AdminDashboard /></ProtectedRoute>} />
        <Route path="/members" element={<ProtectedRoute><MemberForm /></ProtectedRoute>} />
      </Routes>
    </Router>
  );
};

const AuthWrapper = () => {
  const token = localStorage.getItem('token');
  const user = JSON.parse(localStorage.getItem('user'));

  if (token && user) {
    return user.role === 'admin' 
      ? <Navigate to="/admin" replace /> 
      : <Navigate to="/dashboard" replace />;
  }
  return <Navigate to="/login" replace />;
};

const ProtectedRoute = ({ children, adminOnly = false }) => {
  const token = localStorage.getItem('token');
  const user = JSON.parse(localStorage.getItem('user'));
  
  if (!token) {
    return <Navigate to={adminOnly ? "/admin-login" : "/login"} replace />;
  }
  
  if (adminOnly && (!user || !user.isAdmin)) {
    return <Navigate to="/admin-login" replace />;
  }
  
  return children;
};

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await axios.post('/api/login', { email, password });
      localStorage.setItem('token', res.data.token);
      localStorage.setItem('user', JSON.stringify(res.data.user));
      window.location.href = res.data.user.role === 'admin' ? '/admin' : '/dashboard';
    } catch (err) {
      setError(err.response?.data?.message || 'Login failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="xs" className="auth-container">
      <Paper elevation={3} className="paper-container">
        <Typography variant="h5" className="auth-title">
          Church Reporting System
        </Typography>
        <Box component="form" onSubmit={handleSubmit} className="auth-form">
          <TextField
            label="Email"
            type="email"
            fullWidth
            margin="normal"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          <TextField
            label="Password"
            type="password"
            fullWidth
            margin="normal"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <Button
            type="submit"
            fullWidth
            variant="contained"
            className="primary-button"
            sx={{ mt: 3, mb: 2 }}
            disabled={loading}
          >
            {loading ? <CircularProgress size={24} /> : 'Login'}
          </Button>
          {error && (
            <Typography color="error" align="center">
              {error}
            </Typography>
          )}
          <Typography className="auth-link">
            Don't have an account? <Link to="/register">Register here</Link>
          </Typography>
          <Typography className="auth-link">
            Admin? <Link to="/admin-login">Admin Login</Link>
          </Typography>
        </Box>
      </Paper>
    </Container>
  );
};

const Register = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    phone: '',
    password: '',
    confirmPassword: '',
    role: 'group_leader',
    group: 'A'
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    try {
      setLoading(true);
      await axios.post('/api/register', {
        name: formData.name,
        email: formData.email,
        phone: formData.phone,
        password: formData.password,
        role: formData.role,
        group: formData.group
      });

      navigate('/login', { state: { success: 'Registration successful! Please login.' } });
    } catch (err) {
      setError(err.response?.data?.message || 'Registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="xs" className="auth-container">
      <Paper elevation={3} className="paper-container">
        <Typography variant="h5" className="auth-title">
          Create Account
        </Typography>
        
        {error && (
          <Typography color="error" align="center" sx={{ mb: 2 }}>
            {error}
          </Typography>
        )}

        <Box component="form" onSubmit={handleSubmit} className="auth-form">
          <TextField
            label="Full Name"
            name="name"
            fullWidth
            margin="normal"
            required
            value={formData.name}
            onChange={handleChange}
          />
          <TextField
            label="Email"
            type="email"
            name="email"
            fullWidth
            margin="normal"
            required
            value={formData.email}
            onChange={handleChange}
          />
          <TextField
            label="Phone Number"
            name="phone"
            fullWidth
            margin="normal"
            required
            value={formData.phone}
            onChange={handleChange}
          />
          <TextField
            label="Password"
            type="password"
            name="password"
            fullWidth
            margin="normal"
            required
            value={formData.password}
            onChange={handleChange}
          />
          <TextField
            label="Confirm Password"
            type="password"
            name="confirmPassword"
            fullWidth
            margin="normal"
            required
            value={formData.confirmPassword}
            onChange={handleChange}
          />
          <FormControl fullWidth margin="normal" required>
            <InputLabel>Role</InputLabel>
            <Select
              name="role"
              value={formData.role}
              label="Role"
              onChange={handleChange}
            >
              <MenuItem value="group_leader">Group Leader</MenuItem>
              <MenuItem value="deputy_leader">Deputy Leader</MenuItem>
            </Select>
          </FormControl>
          <FormControl fullWidth margin="normal" required>
            <InputLabel>Group</InputLabel>
            <Select
              name="group"
              value={formData.group}
              label="Group"
              onChange={handleChange}
            >
              <MenuItem value="A">Group A (Mercy Center)</MenuItem>
              <MenuItem value="B">Group B (Grace Center)</MenuItem>
            </Select>
          </FormControl>
          <Button
            type="submit"
            fullWidth
            variant="contained"
            className="primary-button"
            sx={{ mt: 3, mb: 2 }}
            disabled={loading}
          >
            {loading ? <CircularProgress size={24} /> : 'Register'}
          </Button>
          <Typography className="auth-link">
            Already have an account? <Link to="/login">Login here</Link>
          </Typography>
        </Box>
      </Paper>
    </Container>
  );
};

const MemberForm = () => {
  const user = JSON.parse(localStorage.getItem('user'));
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    name: '',
    phone: '',
    group: user?.group || 'A'
  });
  const [members, setMembers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [editMode, setEditMode] = useState(false);
  const [currentMemberId, setCurrentMemberId] = useState(null);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [memberToDelete, setMemberToDelete] = useState(null);

  useEffect(() => { 
    fetchMembers(); 
  }, []);

  useEffect(() => {
    if (user?.role !== 'admin') {
      navigate('/dashboard');
    }
  }, [user, navigate]);

  const fetchMembers = async () => {
    try {
      setLoading(true);
      const res = await axios.get('/api/members', {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });
      setMembers(res.data);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to fetch members');
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      setLoading(true);
      setError('');
      setSuccess('');

      if (!formData.name.trim() || !formData.phone.trim()) {
        throw new Error('Name and phone are required');
      }

      const payload = {
        name: formData.name.trim(),
        phone: formData.phone.trim(),
        group: user.role === 'admin' ? formData.group : user.group
      };

      const config = {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      };

      if (editMode) {
        await axios.put(`/api/members/${currentMemberId}`, payload, config);
        setSuccess('Member updated successfully!');
      } else {
        await axios.post('/api/members', payload, config);
        setSuccess('Member added successfully!');
      }
      
      resetForm();
      fetchMembers();
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = (member) => {
    setFormData({
      name: member.name,
      phone: member.phone,
      group: member.group
    });
    setCurrentMemberId(member._id);
    setEditMode(true);
  };

  const handleDeleteClick = (member) => {
    setMemberToDelete(member);
    setDeleteConfirmOpen(true);
  };

  const handleDeleteConfirm = async () => {
    try {
      setLoading(true);
      await axios.delete(`/api/members/${memberToDelete._id}`, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });
      setSuccess('Member deleted successfully!');
      fetchMembers();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to delete member');
    } finally {
      setLoading(false);
      setDeleteConfirmOpen(false);
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      phone: '',
      group: user.group || 'A'
    });
    setEditMode(false);
    setCurrentMemberId(null);
  };

  return (
    <Container maxWidth="lg">
      <Paper className="paper-container">
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
          <Typography variant="h5">
            {editMode ? 'Edit Member' : 'Add New Member'}
          </Typography>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={fetchMembers}
            disabled={loading}
          >
            Refresh
          </Button>
        </Box>
        
        <Box component="form" onSubmit={handleSubmit}>
          <TextField
            label="Full Name"
            name="name"
            fullWidth
            margin="normal"
            required
            value={formData.name}
            onChange={handleInputChange}
          />
          <TextField
            label="Phone Number"
            name="phone"
            fullWidth
            margin="normal"
            required
            value={formData.phone}
            onChange={handleInputChange}
          />
          <FormControl fullWidth margin="normal" required>
            <InputLabel>Group</InputLabel>
            <Select
              name="group"
              value={formData.group}
              label="Group"
              onChange={handleInputChange}
              disabled={user.role !== 'admin'}
            >
              <MenuItem value="A">Group A (Mercy Center)</MenuItem>
              <MenuItem value="B">Group B (Grace Center)</MenuItem>
            </Select>
          </FormControl>

          <Box mt={3} display="flex" gap={2}>
            <Button
              type="submit"
              variant="contained"
              className="primary-button"
              disabled={loading}
              startIcon={!loading && <AddIcon />}
              sx={{ mt: 2 }}
            >
              {loading ? (
                <CircularProgress size={24} color="inherit" />
              ) : editMode ? (
                'Update Member'
              ) : (
                'Add Member'
              )}
            </Button>
            {editMode && (
              <Button
                variant="outlined"
                onClick={resetForm}
                disabled={loading}
              >
                Cancel
              </Button>
            )}
          </Box>
        </Box>
      </Paper>

      <Paper className="paper-container">
        <Typography variant="h5" gutterBottom>
          Member List ({members.length})
        </Typography>

        <TableContainer className="responsive-table">
          <Table className="data-table">
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Phone</TableCell>
                <TableCell>Group</TableCell>
                <TableCell align="center">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {members.length > 0 ? (
                members.map((member) => (
                  <TableRow key={member._id} hover className="member-row">
                    <TableCell>{member.name}</TableCell>
                    <TableCell>{member.phone}</TableCell>
                    <TableCell>{member.group === 'A' ? 'Mercy Center' : 'Grace Center'}</TableCell>
                    <TableCell align="center">
                      <Tooltip title="Edit">
                        <IconButton
                          color="primary"
                          onClick={() => handleEdit(member)}
                          disabled={loading}
                        >
                          <EditIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Delete">
                        <IconButton
                          color="error"
                          onClick={() => handleDeleteClick(member)}
                          disabled={loading}
                        >
                          <DeleteIcon />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={4} align="center">
                    No members found
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      <Dialog
        open={deleteConfirmOpen}
        onClose={() => setDeleteConfirmOpen(false)}
      >
        <DialogTitle>Confirm Delete</DialogTitle>
        <DialogContent>
          Are you sure you want to delete {memberToDelete?.name}?
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteConfirmOpen(false)}>Cancel</Button>
          <Button 
            onClick={handleDeleteConfirm} 
            color="error"
            variant="contained"
            disabled={loading}
          >
            {loading ? <CircularProgress size={24} /> : 'Delete'}
          </Button>
        </DialogActions>
      </Dialog>

      <Snackbar
        open={!!error}
        autoHideDuration={6000}
        onClose={() => setError('')}
      >
        <Alert severity="error" onClose={() => setError('')}>
          {error}
        </Alert>
      </Snackbar>

      <Snackbar
        open={!!success}
        autoHideDuration={3000}
        onClose={() => setSuccess('')}
      >
        <Alert severity="success" onClose={() => setSuccess('')}>
          {success}
        </Alert>
      </Snackbar>
    </Container>
  );
};

const Dashboard = () => {
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [activeTab, setActiveTab] = useState('report');
  const [members, setMembers] = useState([]);
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [month, setMonth] = useState(new Date().toLocaleString('default', { month: 'long' }));
  const [year, setYear] = useState(new Date().getFullYear());
  const [contactStatus, setContactStatus] = useState({});
  const [feedback, setFeedback] = useState({});
  const [submittedMembers, setSubmittedMembers] = useState({});
  const user = JSON.parse(localStorage.getItem('user'));
  const navigate = useNavigate();

  const months = [
    'January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December'
  ];
  const years = Array.from({ length: 10 }, (_, i) => new Date().getFullYear() - i);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        
        // Fetch members
        const membersRes = await axios.get('/api/members', {
          headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
        });
        setMembers(membersRes.data);

        // Initialize contact status and feedback
        const initialStatus = {};
        const initialFeedback = {};
        const initialSubmitted = {};
        
        membersRes.data.forEach(member => {
          initialStatus[member._id] = false;
          initialFeedback[member._id] = '';
          initialSubmitted[member._id] = false;
        });
        
        setContactStatus(initialStatus);
        setFeedback(initialFeedback);
        setSubmittedMembers(initialSubmitted);

        // Fetch reports for current month/year
        const reportsRes = await axios.get('/api/reports', {
          params: { month, year },
          headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
        });
        
        if (reportsRes.data.length > 0) {
          const report = reportsRes.data[0];
          const updatedSubmitted = {...initialSubmitted};
          
          // Check if member was already submitted
          report.leaderReport?.contacts?.forEach(contact => {
            if (contact.contacted) {
              updatedSubmitted[contact.memberId] = true;
            }
          });
          
          report.deputyReport?.contacts?.forEach(contact => {
            if (contact.contacted) {
              updatedSubmitted[contact.memberId] = true;
            }
          });
          
          setSubmittedMembers(updatedSubmitted);
        }
      } catch (err) {
        setError(err.response?.data?.message || 'Failed to fetch data');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [month, year]);

 const handleSubmitMemberReport = async (memberId, isLeaderReport) => {
  try {
    setLoading(true);
    
    const config = {
      headers: { 
        Authorization: `Bearer ${localStorage.getItem('token')}`,
        'Content-Type': 'application/json'
      }
    };

    const response = await axios.post('/api/reports/member', {
      month,
      year,
      memberId,
      contacted: contactStatus[memberId] || false,
      feedback: feedback[memberId] || '',
      isLeaderReport  // This should be true for leader, false for deputy
    }, config);

      setSubmittedMembers(prev => ({
        ...prev,
        [memberId]: true
      }));
      
      setSuccess('Member report submitted successfully!');
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      console.error('Report submission error:', err);
      setError(err.response?.data?.message || err.message || 'Failed to submit report');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = '/login';
  };

  return (
    <Box sx={{ display: 'flex' }}>
      <AppBar position="fixed" sx={{ zIndex: (theme) => theme.zIndex.drawer + 1 }}>
        <Toolbar>
          <IconButton
            color="inherit"
            edge="start"
            onClick={() => setDrawerOpen(true)}
            sx={{ mr: 2 }}
          >
            <MenuIcon />
          </IconButton>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            {user.group === 'A' ? 'Mercy Center' : 'Grace Center'} - {user.name}
          </Typography>
          <IconButton color="inherit" onClick={handleLogout}>
            <ExitToAppIcon />
          </IconButton>
        </Toolbar>
      </AppBar>

      <Drawer
        anchor="left"
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
      >
        <Box sx={{ width: 250, p: 2 }}>
          <Typography variant="h6" sx={{ p: 2 }}>
            Menu
          </Typography>
          <Divider />
          <List>
            <ListItem 
              button 
              selected={activeTab === 'report'}
              onClick={() => {
                setActiveTab('report');
                setDrawerOpen(false);
              }}
            >
              <ListItemText primary="Submit Report" />
            </ListItem>
            <ListItem 
              button 
              selected={activeTab === 'history'}
              onClick={() => {
                setActiveTab('history');
                setDrawerOpen(false);
              }}
            >
              <ListItemText primary="Report History" />
            </ListItem>
          </List>
        </Box>
      </Drawer>

      <Box component="main" className="main-content">
        {activeTab === 'report' && (
          <Box className="paper-container">
            <Typography variant="h4" className="page-title">
              Monthly Contact Report - {month} {year}
            </Typography>
            
            <Box className="filter-container">
              <FormControl sx={{ minWidth: 120 }}>
                <InputLabel>Month</InputLabel>
                <Select
                  value={month}
                  onChange={(e) => setMonth(e.target.value)}
                  label="Month"
                >
                  {months.map(m => (
                    <MenuItem key={m} value={m}>{m}</MenuItem>
                  ))}
                </Select>
              </FormControl>
              
              <FormControl sx={{ minWidth: 120 }}>
                <InputLabel>Year</InputLabel>
                <Select
                  value={year}
                  onChange={(e) => setYear(e.target.value)}
                  label="Year"
                >
                  {years.map(y => (
                    <MenuItem key={y} value={y}>{y}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Box>

            <TableContainer component={Paper} className="data-table">
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Member Name</TableCell>
                    <TableCell>Phone</TableCell>
                    <TableCell>Contacted</TableCell>
                    <TableCell>Feedback</TableCell>
                    <TableCell align="right">Action</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {members.map((member) => (
                    <TableRow key={member._id} className="member-row">
                      <TableCell>{member.name}</TableCell>
                      <TableCell>{member.phone}</TableCell>
                      <TableCell>
                        <Checkbox
                          checked={contactStatus[member._id] || false}
                          onChange={(e) => setContactStatus({
                            ...contactStatus,
                            [member._id]: e.target.checked
                          })}
                          disabled={submittedMembers[member._id]}
                        />
                      </TableCell>
                      <TableCell>
                        <TextField
                          fullWidth
                          size="small"
                          value={feedback[member._id] || ''}
                          onChange={(e) => setFeedback({
                            ...feedback,
                            [member._id]: e.target.value
                          })}
                          disabled={submittedMembers[member._id]}
                        />
                      </TableCell>
                      <TableCell align="right">
                        {submittedMembers[member._id] ? (
                          <Button 
                            variant="contained" 
                            className="submitted-btn submit-btn"
                            disabled
                          >
                            Submitted
                          </Button>
                        ) : (
                          <Button
                            variant="contained"
                            className="primary-button submit-btn"
                            onClick={() => handleSubmitMemberReport(
                              member._id, 
                              user.role === 'group_leader'
                            )}
                            disabled={loading}
                          >
                            {loading ? <CircularProgress size={24} color="inherit" /> : 'Submit'}
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        )}

        {activeTab === 'history' && (
          <Box className="paper-container">
            <Typography variant="h4" className="page-title">
              Report History
            </Typography>
            
            <Box className="filter-container">
              <FormControl sx={{ minWidth: 120 }}>
                <InputLabel>Month</InputLabel>
                <Select
                  value={month}
                  onChange={(e) => setMonth(e.target.value)}
                  label="Month"
                >
                  {months.map(m => (
                    <MenuItem key={m} value={m}>{m}</MenuItem>
                  ))}
                </Select>
              </FormControl>
              
              <FormControl sx={{ minWidth: 120 }}>
                <InputLabel>Year</InputLabel>
                <Select
                  value={year}
                  onChange={(e) => setYear(e.target.value)}
                  label="Year"
                >
                  {years.map(y => (
                    <MenuItem key={y} value={y}>{y}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Box>

            {reports.length > 0 ? (
              <TableContainer component={Paper} className="data-table">
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Member</TableCell>
                      <TableCell>Leader Contacted</TableCell>
                      <TableCell>Leader Feedback</TableCell>
                      <TableCell>Deputy Contacted</TableCell>
                      <TableCell>Deputy Feedback</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {reports[0].leaderReport.contacts.map((contact, index) => {
                      const deputyContact = reports[0].deputyReport?.contacts?.[index];
                      return (
                        <TableRow key={contact.memberId._id}>
                          <TableCell>{contact.memberId.name}</TableCell>
                          <TableCell>{contact.contacted ? 'Yes' : 'No'}</TableCell>
                          <TableCell>{contact.feedback || '-'}</TableCell>
                          <TableCell>{deputyContact?.contacted ? 'Yes' : 'No'}</TableCell>
                          <TableCell>{deputyContact?.feedback || '-'}</TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </TableContainer>
            ) : (
              <Typography>No reports found for selected month/year</Typography>
            )}
          </Box>
        )}

        <Snackbar
          open={!!error}
          autoHideDuration={6000}
          onClose={() => setError('')}
        >
          <Alert severity="error" onClose={() => setError('')}>
            {error}
          </Alert>
        </Snackbar>

        <Snackbar
          open={!!success}
          autoHideDuration={3000}
          onClose={() => setSuccess('')}
        >
          <Alert severity="success" onClose={() => setSuccess('')}>
            {success}
          </Alert>
        </Snackbar>
      </Box>
    </Box>
  );
};

const AdminDashboard = () => {
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [activeTab, setActiveTab] = useState('reports');
  const [reports, setReports] = useState([]);
  const [reportMonth, setReportMonth] = useState(new Date().toLocaleString('default', { month: 'long' }));
  const [reportYear, setReportYear] = useState(new Date().getFullYear());
  const [reportGroup, setReportGroup] = useState('All');
  const [members, setMembers] = useState([]);
  const [memberGroup, setMemberGroup] = useState('All');
  const [memberForm, setMemberForm] = useState({
    name: '',
    phone: '',
    group: 'A'
  });
  const [editMemberId, setEditMemberId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [itemToDelete, setItemToDelete] = useState(null);

  const months = [
    'January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December'
  ];
  const years = Array.from({ length: 10 }, (_, i) => new Date().getFullYear() - i);

  useEffect(() => {
    if (activeTab === 'reports') {
      fetchReports();
    } else {
      fetchMembers();
    }
  }, [activeTab, reportMonth, reportYear, reportGroup, memberGroup]);

  const fetchReports = async () => {
    try {
      setLoading(true);
      const params = {
        month: reportMonth,
        year: reportYear,
        group: reportGroup === 'All' ? '' : reportGroup
      };
      
      const res = await axios.get('/api/reports', {
        params,
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });
      
      setReports(res.data);
    } catch (err) {
      setError(err.response?.data?.message || "Failed to fetch reports");
    } finally {
      setLoading(false);
    }
  };

  const fetchMembers = async () => {
    try {
      setLoading(true);
      const params = {};
      
      if (memberGroup !== 'All') {
        params.group = memberGroup;
      }
      
      const res = await axios.get('/api/members', {
        params,
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });
      setMembers(res.data);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to fetch members');
    } finally {
      setLoading(false);
    }
  };

  const handleMemberSubmit = async (e) => {
    e.preventDefault();
    try {
      setLoading(true);
      
      if (editMemberId) {
        await axios.put(`/api/members/${editMemberId}`, memberForm, {
          headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
        });
        setSuccess('Member updated successfully!');
      } else {
        await axios.post('/api/members', memberForm, {
          headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
        });
        setSuccess('Member added successfully!');
      }
      
      resetMemberForm();
      fetchMembers();
    } catch (err) {
      setError(err.response?.data?.message || 'Operation failed');
    } finally {
      setLoading(false);
    }
  };

  const resetMemberForm = () => {
    setMemberForm({ name: '', phone: '', group: 'A' });
    setEditMemberId(null);
  };

  const handleDelete = async () => {
    try {
      setLoading(true);
      await axios.delete(`/api/members/${itemToDelete}`, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });
      setSuccess('Member deleted successfully!');
      fetchMembers();
    } catch (err) {
      setError('Deletion failed: ' + (err.message || 'Server error'));
    } finally {
      setLoading(false);
      setDeleteConfirmOpen(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = '/admin-login';
  };

  return (
    <Box sx={{ display: 'flex' }}>
      <AppBar position="fixed" sx={{ zIndex: (theme) => theme.zIndex.drawer + 1 }}>
        <Toolbar>
          <IconButton
            color="inherit"
            edge="start"
            onClick={() => setDrawerOpen(true)}
            sx={{ mr: 2 }}
          >
            <MenuIcon />
          </IconButton>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            Admin Dashboard
          </Typography>
          <IconButton color="inherit" onClick={handleLogout}>
            <ExitToAppIcon />
          </IconButton>
        </Toolbar>
      </AppBar>

      <Drawer
        anchor="left"
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
      >
        <Box sx={{ width: 250, p: 2 }}>
          <Typography variant="h6" sx={{ p: 2 }}>
            Admin Menu
          </Typography>
          <Divider />
          <List>
            <ListItem 
              button 
              selected={activeTab === 'reports'}
              onClick={() => {
                setActiveTab('reports');
                setDrawerOpen(false);
              }}
            >
              <ListItemText primary="View Reports" />
            </ListItem>
            <ListItem 
              button 
              selected={activeTab === 'members'}
              onClick={() => {
                setActiveTab('members');
                setDrawerOpen(false);
              }}
            >
              <ListItemText primary="Manage Members" />
            </ListItem>
          </List>
        </Box>
      </Drawer>

      <Box component="main" className="main-content">
        {activeTab === 'reports' && (
          <Paper className="paper-container">
            <Typography variant="h4" className="page-title">
              Monthly Reports
            </Typography>
            
            <Box className="filter-container">
              <FormControl sx={{ minWidth: 120 }}>
                <InputLabel>Month</InputLabel>
                <Select
                  value={reportMonth}
                  onChange={(e) => setReportMonth(e.target.value)}
                  label="Month"
                >
                  {months.map(m => (
                    <MenuItem key={m} value={m}>{m}</MenuItem>
                  ))}
                </Select>
              </FormControl>
              
              <FormControl sx={{ minWidth: 120 }}>
                <InputLabel>Year</InputLabel>
                <Select
                  value={reportYear}
                  onChange={(e) => setReportYear(e.target.value)}
                  label="Year"
                >
                  {years.map(y => (
                    <MenuItem key={y} value={y}>{y}</MenuItem>
                  ))}
                </Select>
              </FormControl>
              
              <FormControl sx={{ minWidth: 120 }}>
                <InputLabel>Group</InputLabel>
                <Select
                  value={reportGroup}
                  onChange={(e) => setReportGroup(e.target.value)}
                  label="Group"
                >
                  <MenuItem value="All">All Groups</MenuItem>
                  <MenuItem value="A">Group A</MenuItem>
                  <MenuItem value="B">Group B</MenuItem>
                </Select>
              </FormControl>
              
              <Button 
                variant="contained" 
                className="primary-button"
                onClick={fetchReports}
                disabled={loading}
                startIcon={<RefreshIcon />}
              >
                Refresh
              </Button>
            </Box>

            {loading ? (
              <Box display="flex" justifyContent="center" my={4}>
                <CircularProgress />
              </Box>
            ) : reports.length > 0 ? (
              reports.map(report => (
                <Box key={`${report.month}-${report.year}-${report.group}`} mb={4}>
                  <Typography variant="h6" gutterBottom>
                    {report.month} {report.year} - Group {report.group}
                  </Typography>
                  
                  <TableContainer component={Paper} className="data-table">
                    <Table>
                      <TableHead>
                        <TableRow>
                          <TableCell>Member</TableCell>
                          <TableCell>Leader Contacted</TableCell>
                          <TableCell>Leader Feedback</TableCell>
                          <TableCell>Deputy Contacted</TableCell>
                          <TableCell>Deputy Feedback</TableCell>
                          <TableCell>Finalized</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {report.leaderReport.contacts.map((contact, index) => {
                          const deputyContact = report.deputyReport?.contacts?.[index];
                          return (
                            <TableRow key={contact.memberId._id}>
                              <TableCell>{contact.memberId.name}</TableCell>
                              <TableCell>{contact.contacted ? 'Yes' : 'No'}</TableCell>
                              <TableCell>{contact.feedback || '-'}</TableCell>
                              <TableCell>{deputyContact?.contacted ? 'Yes' : 'No'}</TableCell>
                              <TableCell>{deputyContact?.feedback || '-'}</TableCell>
                              <TableCell>{report.finalSubmission ? 'Yes' : 'No'}</TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Box>
              ))
            ) : (
              <Typography>No reports found for selected criteria</Typography>
            )}
          </Paper>
        )}

        {activeTab === 'members' && (
          <>
            <Typography variant="h4" className="page-title">
              Member Management
            </Typography>
            
            <Paper className="paper-container">
              <Typography variant="h5" className="section-title">
                {editMemberId ? 'Edit Member' : 'Add New Member'}
              </Typography>
              
              <Box component="form" onSubmit={handleMemberSubmit}>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <TextField
                      label="Full Name"
                      name="name"
                      fullWidth
                      margin="normal"
                      required
                      value={memberForm.name}
                      onChange={(e) => setMemberForm({...memberForm, name: e.target.value})}
                    />
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <TextField
                      label="Phone Number"
                      name="phone"
                      fullWidth
                      margin="normal"
                      required
                      value={memberForm.phone}
                      onChange={(e) => setMemberForm({...memberForm, phone: e.target.value})}
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <FormControl fullWidth margin="normal" required>
                      <InputLabel>Group</InputLabel>
                      <Select
                        name="group"
                        value={memberForm.group}
                        label="Group"
                        onChange={(e) => setMemberForm({...memberForm, group: e.target.value})}
                      >
                        <MenuItem value="A">Group A (Mercy Center)</MenuItem>
                        <MenuItem value="B">Group B (Grace Center)</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                </Grid>

                <Box mt={3} display="flex" gap={2}>
                  <Button
                    type="submit"
                    variant="contained"
                    className="primary-button"
                    disabled={loading}
                    startIcon={!loading && <AddIcon />}
                  >
                    {loading ? <CircularProgress size={24} /> : editMemberId ? 'Update' : 'Add Member'}
                  </Button>
                  {editMemberId && (
                    <Button
                      variant="outlined"
                      onClick={resetMemberForm}
                      disabled={loading}
                    >
                      Cancel
                    </Button>
                  )}
                </Box>
              </Box>
            </Paper>

            <Paper className="paper-container">
              <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
                <Typography variant="h5" className="section-title">
                  All Members ({members.length})
                </Typography>
                <FormControl sx={{ minWidth: 120 }}>
                  <InputLabel>Filter Group</InputLabel>
                  <Select
                    value={memberGroup}
                    onChange={(e) => setMemberGroup(e.target.value)}
                    label="Filter Group"
                  >
                    <MenuItem value="All">All Groups</MenuItem>
                    <MenuItem value="A">Group A</MenuItem>
                    <MenuItem value="B">Group B</MenuItem>
                  </Select>
                </FormControl>
              </Box>
              
              <TableContainer className="responsive-table">
                <Table className="data-table">
                  <TableHead>
                    <TableRow>
                      <TableCell>Name</TableCell>
                      <TableCell>Phone</TableCell>
                      <TableCell>Group</TableCell>
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {members.length > 0 ? (
                      members.map((member) => (
                        <TableRow key={member._id} hover className="member-row">
                          <TableCell>{member.name}</TableCell>
                          <TableCell>{member.phone}</TableCell>
                          <TableCell>
                            <Chip 
                              label={member.group === 'A' ? 'Mercy Center' : 'Grace Center'} 
                              color={member.group === 'A' ? 'primary' : 'secondary'} 
                            />
                          </TableCell>
                          <TableCell align="right">
                            <Tooltip title="Edit">
                              <IconButton
                                color="primary"
                                onClick={() => {
                                  setMemberForm({
                                    name: member.name,
                                    phone: member.phone,
                                    group: member.group
                                  });
                                  setEditMemberId(member._id);
                                }}
                              >
                                <EditIcon />
                              </IconButton>
                            </Tooltip>
                            <Tooltip title="Delete">
                              <IconButton
                                color="error"
                                onClick={() => {
                                  setItemToDelete(member._id);
                                  setDeleteConfirmOpen(true);
                                }}
                              >
                                <DeleteIcon />
                              </IconButton>
                            </Tooltip>
                          </TableCell>
                        </TableRow>
                      ))
                    ) : (
                      <TableRow>
                        <TableCell colSpan={4} align="center">
                          No members found
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </>
        )}

        <Dialog open={deleteConfirmOpen} onClose={() => setDeleteConfirmOpen(false)}>
          <DialogTitle>Confirm Delete</DialogTitle>
          <DialogContent>
            Are you sure you want to delete this member? This action cannot be undone.
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setDeleteConfirmOpen(false)}>Cancel</Button>
            <Button 
              onClick={handleDelete} 
              color="error"
              variant="contained"
              disabled={loading}
            >
              {loading ? <CircularProgress size={24} /> : 'Delete'}
            </Button>
          </DialogActions>
        </Dialog>

        <Snackbar open={!!error} autoHideDuration={6000} onClose={() => setError('')}>
          <Alert severity="error" onClose={() => setError('')}>{error}</Alert>
        </Snackbar>
        
        <Snackbar open={!!success} autoHideDuration={3000} onClose={() => setSuccess('')}>
          <Alert severity="success" onClose={() => setSuccess('')}>{success}</Alert>
        </Snackbar>
      </Box>
    </Box>
  );
};

const AdminLogin = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await axios.post('/api/admin/login', { email, password });
      localStorage.setItem('token', res.data.token);
      localStorage.setItem('user', JSON.stringify(res.data.user));
      window.location.href = '/admin';
    } catch (err) {
      setError(err.response?.data?.message || 'Admin login failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="xs" className="auth-container">
      <Paper elevation={3} className="paper-container">
        <Typography variant="h5" className="auth-title">
          Admin Login
        </Typography>
        <Box component="form" onSubmit={handleSubmit} className="auth-form">
          <TextField
            label="Admin Email"
            type="email"
            fullWidth
            margin="normal"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          <TextField
            label="Password"
            type="password"
            fullWidth
            margin="normal"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <Button
            type="submit"
            fullWidth
            variant="contained"
            className="primary-button"
            sx={{ mt: 3, mb: 2 }}
            disabled={loading}
          >
            {loading ? <CircularProgress size={24} /> : 'Login'}
          </Button>
          {error && (
            <Typography color="error" align="center">
              {error}
            </Typography>
          )}
          <Typography className="auth-link">
            <Link to="/admin-register">Register as Admin</Link>
          </Typography>
        </Box>
      </Paper>
    </Container>
  );
};

const AdminRegister = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    phone: '',
    password: '',
    confirmPassword: '',
    secretKey: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    try {
      setLoading(true);
      await axios.post('/api/admin/register', {
        name: formData.name,
        email: formData.email,
        phone: formData.phone,
        password: formData.password,
        secretKey: formData.secretKey
      });

      navigate('/admin-login', { state: { success: 'Admin registration successful! Please login.' } });
    } catch (err) {
      setError(err.response?.data?.message || 'Admin registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="xs" className="auth-container">
      <Paper elevation={3} className="paper-container">
        <Typography variant="h5" className="auth-title">
          Admin Registration
        </Typography>
        
        {error && (
          <Typography color="error" align="center" sx={{ mb: 2 }}>
            {error}
          </Typography>
        )}

        <Box component="form" onSubmit={handleSubmit} className="auth-form">
          <TextField
            label="Full Name"
            name="name"
            fullWidth
            margin="normal"
            required
            value={formData.name}
            onChange={handleChange}
          />
          <TextField
            label="Email"
            type="email"
            name="email"
            fullWidth
            margin="normal"
            required
            value={formData.email}
            onChange={handleChange}
          />
          <TextField
            label="Phone Number"
            name="phone"
            fullWidth
            margin="normal"
            required
            value={formData.phone}
            onChange={handleChange}
          />
          <TextField
            label="Password"
            type="password"
            name="password"
            fullWidth
            margin="normal"
            required
            value={formData.password}
            onChange={handleChange}
          />
          <TextField
            label="Confirm Password"
            type="password"
            name="confirmPassword"
            fullWidth
            margin="normal"
            required
            value={formData.confirmPassword}
            onChange={handleChange}
          />
          <TextField
            label="Admin Secret Key"
            type="password"
            name="secretKey"
            fullWidth
            margin="normal"
            required
            value={formData.secretKey}
            onChange={handleChange}
          />
          <Button
            type="submit"
            fullWidth
            variant="contained"
            className="primary-button"
            sx={{ mt: 3, mb: 2 }}
            disabled={loading}
          >
            {loading ? <CircularProgress size={24} /> : 'Register Admin'}
          </Button>
          <Typography className="auth-link">
            Already have an account? <Link to="/admin-login">Admin Login</Link>
          </Typography>
        </Box>
      </Paper>
    </Container>
  );
};

export default App;