import React, { useState, useEffect} from 'react';
import axios from 'axios';

import { BrowserRouter as Router, Route, Routes, Navigate, Link ,useNavigate} from 'react-router-dom';
import {
  Container, Box, Typography, TextField, Button, Checkbox,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper,
  Select, MenuItem, InputLabel, FormControl, Snackbar, Alert, CircularProgress,
  AppBar, Toolbar, IconButton, Drawer, List, ListItem, ListItemText, Divider,
 Grid, Dialog, DialogTitle, DialogContent, DialogActions,Card,
  CardContent,Chip,Tooltip
} from '@mui/material';



import { Menu as MenuIcon, BarChart as BarChartIcon, 
  ExitToApp as ExitToAppIcon, Description as DescriptionIcon } from '@mui/icons-material';

import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Title, Legend } from 'chart.js';


import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import EditIcon from '@mui/icons-material/Edit';
import RefreshIcon from '@mui/icons-material/Refresh';

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Legend);

// // Base URL for API
// axios.defaults.baseURL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

axios.defaults.baseURL = process.env.NODE_ENV === 'production' 
  ? process.env.REACT_APP_API_URL 
  : 'http://localhost:5000';

const App = () => {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<AuthWrapper />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
        <Route path="/admin" element={<AdminDashboard />} />
        <Route path="/members" element={<ProtectedRoute><MemberForm /></ProtectedRoute>} />
      </Routes>
    </Router>
  );
};

// import React, { useState, useEffect } from 'react';
// import axios from 'axios';
// import {
//   Container, Box, Typography, TextField, Button, Checkbox,
//   Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper,
//   Select, MenuItem, InputLabel, FormControl, Snackbar, Alert, CircularProgress,
//   IconButton, Tooltip, Dialog, DialogTitle, DialogContent, DialogActions
// } from '@mui/material';
// import AddIcon from '@mui/icons-material/Add';
// import DeleteIcon from '@mui/icons-material/Delete';
// import EditIcon from '@mui/icons-material/Edit';
// import RefreshIcon from '@mui/icons-material/Refresh';

const MemberForm = () => {
  const user = JSON.parse(localStorage.getItem('user'));
  const [formData, setFormData] = useState({
    name: '',
    phone: '',
    group: user.group || 'A'
  });
  const [members, setMembers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [editMode, setEditMode] = useState(false);
  const [currentMemberId, setCurrentMemberId] = useState(null);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [memberToDelete, setMemberToDelete] = useState(null);

  // Fetch members on load
  useEffect(() => { 
    fetchMembers(); 
  }, []);

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

        // Basic validation
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

        let response;
        if (editMode) {
            response = await axios.put(`/api/members/${currentMemberId}`, payload, config);
        } else {
            response = await axios.post('/api/members', payload, config); // Ensure this is correct
        }

        setSuccess(editMode ? 'Member updated successfully!' : 'Member added successfully!');
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
      <Paper elevation={3} sx={{ p: 4, mb: 4 }}>
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

      <Paper elevation={3} sx={{ p: 4 }}>
        <Typography variant="h5" gutterBottom>
          Member List ({members.length})
        </Typography>

        <TableContainer>
          <Table>
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
                  <TableRow key={member._id} hover>
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
  
  if (adminOnly && (!token || !user || user.role !== 'admin')) {
    return <Navigate to="/login" replace />;
  }
  
  if (!adminOnly && !token) {
    return <Navigate to="/login" replace />;
  }
  
  return children;
};


const Register = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    phone: '',
    password: '',
    confirmPassword: '',
    role: '',
    group: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    // Validation
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
      setError(err.response?.data?.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  }
 return (
    <Container maxWidth="xs" sx={{ mt: 8 }}>
      <Paper elevation={3} sx={{ p: 4 }}>
        <Typography variant="h5" align="center" gutterBottom>
          Register New User
        </Typography>
        
        {error && (
          <Typography color="error" align="center" sx={{ mb: 2 }}>
            {error}
          </Typography>
        )}

        <Box component="form" onSubmit={handleSubmit} sx={{ mt: 2 }}>
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
            color="primary"
            sx={{ mt: 3, mb: 2 }}
            disabled={loading}
          >
            {loading ? <CircularProgress size={24} /> : 'Register'}
          </Button>
          
          <Typography align="center">
            Already have an account? <Link to="/login">Login here</Link>
          </Typography>
        </Box>
        <Typography align="center" sx={{ mt: 2 }}>
  Don't have an account? <Link href="/register">Register here</Link>
</Typography>
      </Paper>
    </Container>
  );
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
      setError(err.response?.data || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="xs" sx={{ mt: 8 }}>
      <Paper elevation={3} sx={{ p: 4 }}>
        <Typography variant="h5" align="center" gutterBottom>
          Church Reporting System Login
        </Typography>
        <Box component="form" onSubmit={handleSubmit} sx={{ mt: 2 }}>
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
            color="primary"
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
        </Box>
      </Paper>
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
  const user = JSON.parse(localStorage.getItem('user'));
  const navigate=useNavigate()

  const months = [
    'January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December'
  ];
  const years = Array.from({ length: 10 }, (_, i) => new Date().getFullYear() - i);

  useEffect(() => {
    const fetchMembers = async () => {
      try {
        setLoading(true);
        const res = await axios.get('/api/members', {
          headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
        });
        setMembers(res.data);

        // Initialize contact status and feedback
        const initialStatus = {};
        const initialFeedback = {};
        res.data.forEach(member => {
          initialStatus[member._id] = false;
          initialFeedback[member._id] = '';
        });
        setContactStatus(initialStatus);
        setFeedback(initialFeedback);
      } catch (err) {
        setError(err.response?.data || 'Failed to fetch members');
      } finally {
        setLoading(false);
      }
    };

 // In your AdminDashboard component


    fetchMembers();
 
  }, [month, year, user.role]);
const handleSubmitReport = async () => {
  try {
    setLoading(true);
    const contacts = members.map(member => ({
      memberId: member._id,
      contacted: contactStatus[member._id] || false,
      feedback: feedback[member._id] || ''
    }));

    const config = {
      headers: { 
        Authorization: `Bearer ${localStorage.getItem('token')}`,
        'Content-Type': 'application/json'
      }
    };

    const response = await axios.post('/api/reports', {
      month,
      year,
      contacts
    }, config);

    setSuccess('Report submitted successfully!');
    setTimeout(() => setSuccess(''), 3000);
  } catch (err) {
    console.error('Report submission error:', err);
    setError(err.response?.data?.message || err.message || 'Failed to submit report');
  } finally {
    setLoading(false);
  }
};
  const handleFinalSubmit = async () => {
    try {
      setLoading(true);
      await axios.post('/api/reports/finalize', {
        month,
        year
      }, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });

      setSuccess('Final submission completed!');
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError(err.response?.data || 'Failed to finalize report');
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
  selected={activeTab === 'members'}
  onClick={() => {
    navigate('/members');
    setDrawerOpen(false);
  }}
>
  <ListItemText primary="Manage Members" />
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

      <Box component="main" sx={{ flexGrow: 1, p: 3, mt: 8 }}>
        {activeTab === 'report' && (
          <Box>
            <Typography variant="h4" gutterBottom>
              Monthly Member Contact Report
            </Typography>
            
            <Box sx={{ display: 'flex', gap: 2, mb: 4 }}>
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

            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Member Name</TableCell>
                    <TableCell>Phone Number</TableCell>
                    <TableCell>Contacted</TableCell>
                    <TableCell>Feedback</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {members.map((member) => (
                    <TableRow key={member._id}>
                      <TableCell>{member.name}</TableCell>
                      <TableCell>{member.phone}</TableCell>
                      <TableCell>
                        <Checkbox
                          checked={contactStatus[member._id] || false}
                          onChange={(e) => setContactStatus({
                            ...contactStatus,
                            [member._id]: e.target.checked
                          })}
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
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            <Box sx={{ mt: 3, display: 'flex', justifyContent: 'flex-end', gap: 2 }}>
              <Button
                variant="contained"
                onClick={handleSubmitReport}
                disabled={loading}
              >
                {loading ? <CircularProgress size={24} /> : 'Submit Report'}
              </Button>
              
              {user.role === 'group_leader' && (
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={handleFinalSubmit}
                  disabled={loading}
                >
                  {loading ? <CircularProgress size={24} /> : 'Final Submission'}
                </Button>
              )}
            </Box>
          </Box>
        )}

        {activeTab === 'history' && (
          <Box>
            <Typography variant="h4" gutterBottom>
              Report History
            </Typography>
            
            <Box sx={{ display: 'flex', gap: 2, mb: 4 }}>
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
              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Member</TableCell>
                      <TableCell>Leader Contacted</TableCell>
                      <TableCell>Leader Feedback</TableCell>
                      <TableCell>Deputy Contacted</TableCell>
                      <TableCell>Deputy Feedback</TableCell>
                      <TableCell>Final Submission</TableCell>
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
                          <TableCell>{reports[0].finalSubmission ? 'Yes' : 'No'}</TableCell>
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



// import React, { useState, useEffect } from 'react';
// import axios from 'axios';
// import {
//   Box, AppBar, Toolbar, IconButton, Typography, Drawer, List, ListItem, 
//   ListItemText, Divider, Container, Paper, Table, TableBody, TableCell, 
//   TableContainer, TableHead, TableRow, FormControl, Select, MenuItem, 
//   InputLabel, Snackbar, Alert, CircularProgress, Button, TextField,
//   Dialog, DialogTitle, DialogContent, DialogActions, Tooltip, Grid, Card, CardContent, Chip
// } from '@mui/material';
// import { 
//   Menu as MenuIcon, 
//   Add as AddIcon,
//   Delete as DeleteIcon,
//   Edit as EditIcon,
//   Refresh as RefreshIcon
// } from '@mui/icons-material';

const AdminDashboard = () => {
  // State for navigation and UI
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [activeTab, setActiveTab] = useState('reports');
  
  // State for reports
  const [reports, setReports] = useState([]);
  const [reportMonth, setReportMonth] = useState(new Date().toLocaleString('default', { month: 'long' }));
  const [reportYear, setReportYear] = useState(new Date().getFullYear());
  const [reportGroup, setReportGroup] = useState('All');
  
  // State for members
  const [members, setMembers] = useState([]);
  const [memberGroup, setMemberGroup] = useState('A');
  const [memberForm, setMemberForm] = useState({
    name: '',
    phone: '',
    group: 'A'
  });
  
  // Common state
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [itemToDelete, setItemToDelete] = useState(null);
  const [editMode, setEditMode] = useState(false);

  // Fetch data based on active tab
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
      const params = new URLSearchParams();
      params.append('month', reportMonth);
      params.append('year', reportYear);
      if (reportGroup !== 'All') params.append('group', reportGroup);

      const res = await axios.get(`/api/reports?${params.toString()}`);
      setReports(res.data);
    } catch (err) {
      setError('Failed to fetch reports: ' + (err.message || 'Server error'));
    } finally {
      setLoading(false);
    }
  };

  const fetchMembers = async () => {
    try {
      setLoading(true);
      const res = await axios.get(`/api/members?group=${memberGroup}`);
      setMembers(res.data);
    } catch (err) {
      setError('Failed to fetch members: ' + (err.message || 'Server error'));
    } finally {
      setLoading(false);
    }
  };

  const handleMemberSubmit = async (e) => {
    e.preventDefault();
    try {
      setLoading(true);
      
      if (editMode) {
        await axios.put(`/api/members/${itemToDelete}`, memberForm);
        setSuccess('Member updated successfully!');
      } else {
        await axios.post('/api/members', memberForm);
        setSuccess('Member added successfully!');
      }
      
      setMemberForm({ name: '', phone: '', group: memberGroup });
      setEditMode(false);
      fetchMembers();
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Operation failed');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async () => {
    try {
      setLoading(true);
      await axios.delete(`/api/members/${itemToDelete}`);
      setSuccess('Item deleted successfully!');
      activeTab === 'reports' ? fetchReports() : fetchMembers();
    } catch (err) {
      setError('Deletion failed: ' + (err.message || 'Server error'));
    } finally {
      setLoading(false);
      setDeleteConfirmOpen(false);
    }
  };

  return (
    <Box sx={{ display: 'flex' }}>
      {/* App Bar */}
      <AppBar position="fixed" sx={{ zIndex: (theme) => theme.zIndex.drawer + 1 }}>
        <Toolbar>
          <IconButton color="inherit" edge="start" onClick={() => setDrawerOpen(true)} sx={{ mr: 2 }}>
            <MenuIcon />
          </IconButton>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            Church Admin Dashboard
          </Typography>
        </Toolbar>
      </AppBar>

      {/* Navigation Drawer */}
      <Drawer anchor="left" open={drawerOpen} onClose={() => setDrawerOpen(false)}>
        <Box sx={{ width: 250, p: 2 }}>
          <Typography variant="h6" sx={{ p: 2 }}>Menu</Typography>
          <Divider />
          <List>
            <ListItem 
              button 
              selected={activeTab === 'reports'}
              onClick={() => setActiveTab('reports')}
            >
              <ListItemText primary="Reports Dashboard" />
            </ListItem>
            <ListItem 
              button 
              selected={activeTab === 'members'}
              onClick={() => setActiveTab('members')}
            >
              <ListItemText primary="Manage Members" />
            </ListItem>
          </List>
        </Box>
      </Drawer>

      {/* Main Content */}
      <Box component="main" sx={{ flexGrow: 1, p: 3, mt: 8 }}>
        {activeTab === 'reports' ? (
          <>
            <Typography variant="h4" gutterBottom>Monthly Reports</Typography>
            
            {/* Reports filtering controls */}
            <Grid container spacing={2} sx={{ mb: 4 }}>
              <Grid item xs={12} md={4}>
                <FormControl fullWidth>
                  <InputLabel>Month</InputLabel>
                  <Select
                    value={reportMonth}
                    onChange={(e) => setReportMonth(e.target.value)}
                    label="Month"
                  >
                    {['January', 'February', 'March', 'April', 'May', 'June',
                      'July', 'August', 'September', 'October', 'November', 'December']
                      .map(m => <MenuItem key={m} value={m}>{m}</MenuItem>)}
                  </Select>
                </FormControl>
              </Grid>
              
              <Grid item xs={12} md={4}>
                <FormControl fullWidth>
                  <InputLabel>Year</InputLabel>
                  <Select
                    value={reportYear}
                    onChange={(e) => setReportYear(e.target.value)}
                    label="Year"
                  >
                    {Array.from({ length: 10 }, (_, i) => new Date().getFullYear() - i)
                      .map(y => <MenuItem key={y} value={y}>{y}</MenuItem>)}
                  </Select>
                </FormControl>
              </Grid>
              
              <Grid item xs={12} md={4}>
                <FormControl fullWidth>
                  <InputLabel>Group</InputLabel>
                  <Select
                    value={reportGroup}
                    onChange={(e) => setReportGroup(e.target.value)}
                    label="Group"
                  >
                    <MenuItem value="All">All Groups</MenuItem>
                    <MenuItem value="A">Group A (Mercy)</MenuItem>
                    <MenuItem value="B">Group B (Grace)</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            </Grid>

            {/* Reports content */}
            {loading ? (
              <CircularProgress />
            ) : reports.length > 0 ? (
              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Month/Year</TableCell>
                      <TableCell>Group</TableCell>
                      <TableCell>Submitted By</TableCell>
                      <TableCell>Status</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {reports.map(report => (
                      <TableRow key={report._id}>
                        <TableCell>{report.month} {report.year}</TableCell>
                        <TableCell>Group {report.group}</TableCell>
                        <TableCell>{report.submittedBy || 'System'}</TableCell>
                        <TableCell>
                          <Chip 
                            label={report.finalized ? 'Finalized' : 'Draft'} 
                            color={report.finalized ? 'success' : 'warning'} 
                          />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            ) : (
              <Typography>No reports found</Typography>
            )}
          </>
        ) : (
          <>
            {/* Members Management */}
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
              <Typography variant="h4">Member Management</Typography>
              <FormControl sx={{ minWidth: 120 }}>
                <Select
                  value={memberGroup}
                  onChange={(e) => setMemberGroup(e.target.value)}
                >
                  <MenuItem value="A">Group A (Mercy)</MenuItem>
                  <MenuItem value="B">Group B (Grace)</MenuItem>
                </Select>
              </FormControl>
            </Box>

            {/* Member Form */}
            <Paper elevation={3} sx={{ p: 4, mb: 4 }}>
              <Typography variant="h5" gutterBottom>
                {editMode ? 'Edit Member' : 'Add New Member'}
              </Typography>
              
              <Box component="form" onSubmit={handleMemberSubmit}>
                <TextField
                  label="Full Name"
                  name="name"
                  fullWidth
                  margin="normal"
                  required
                  value={memberForm.name}
                  onChange={(e) => setMemberForm({...memberForm, name: e.target.value})}
                />
                <TextField
                  label="Phone Number"
                  name="phone"
                  fullWidth
                  margin="normal"
                  required
                  value={memberForm.phone}
                  onChange={(e) => setMemberForm({...memberForm, phone: e.target.value})}
                />
                
                <Box mt={3} display="flex" gap={2}>
                  <Button
                    type="submit"
                    variant="contained"
                    disabled={loading}
                    startIcon={!loading && <AddIcon />}
                  >
                    {loading ? <CircularProgress size={24} /> : editMode ? 'Update' : 'Add Member'}
                  </Button>
                  {editMode && (
                    <Button
                      variant="outlined"
                      onClick={() => {
                        setMemberForm({ name: '', phone: '', group: memberGroup });
                        setEditMode(false);
                      }}
                    >
                      Cancel
                    </Button>
                  )}
                </Box>
              </Box>
            </Paper>

            {/* Members List */}
            <Paper elevation={3} sx={{ p: 4 }}>
              <Typography variant="h5" gutterBottom>
                {memberGroup === 'A' ? 'Mercy Center' : 'Grace Center'} Members
              </Typography>
              
              {loading ? (
                <CircularProgress />
              ) : members.length > 0 ? (
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Name</TableCell>
                        <TableCell>Phone</TableCell>
                        <TableCell align="right">Actions</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {members.map(member => (
                        <TableRow key={member._id}>
                          <TableCell>{member.name}</TableCell>
                          <TableCell>{member.phone}</TableCell>
                          <TableCell align="right">
                            <Tooltip title="Edit">
                              <IconButton
                                onClick={() => {
                                  setMemberForm({
                                    name: member.name,
                                    phone: member.phone,
                                    group: member.group
                                  });
                                  setEditMode(true);
                                  setItemToDelete(member._id);
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
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              ) : (
                <Typography>No members found in this group</Typography>
              )}
            </Paper>
          </>
        )}

        {/* Common Dialog and Snackbars */}
        <Dialog open={deleteConfirmOpen} onClose={() => setDeleteConfirmOpen(false)}>
          <DialogTitle>Confirm Delete</DialogTitle>
          <DialogContent>
            Are you sure you want to delete this {activeTab === 'reports' ? 'report' : 'member'}?
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

export default App;