const express = require("express");
const session = require("express-session");
const sessionConfig = require("./src/middlewares/sessionConfig");
const path = require("path");
const cookieParser = require("cookie-parser");
require("dotenv").config();
const dashboardRoutes = require("./src/routes/dashboardRoutes");

const proposalSalesRoutes = require("./src/routes/proposalsSalesRoutes");

const loginRoutes = require("./src/routes/loginRoutes");
const flash = require("connect-flash");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const { Sequelize, DataTypes } = require("sequelize");
const cloudinary = require("./src/config/cloudinaryConfig"); 
const app = express();
const api = require("./src/controllers/api.controller");
const moment = require("moment-timezone");
const axios = require("axios");


// for customer
const customerRoutes = require('./src/routes/customerRoutes');
// const customerScreenRoutes = require('./src/routes/customerScreen');

//for suparAdminRoutes rolle
const suparAdminRoutes = require('./src/routes/suparAdminRoutes');

//for salesadmin rolle
const salesadmin = require('./src/routes/salesadmin');

const PORT = 3000; // or any port you prefer
const {
  getStatus,
  getScreenById,
  deviceConfig,
} = require("./src/models/newScreen.model");
const { viewPlaylist } = require("./src/models/playlists.model");
const db = require("./src/config/dbConnection");
const { createHash } = require("crypto");
// Database setup
const sequelize = new Sequelize(
  "dbzvtfeophlfnr",
  "u3m7grklvtlo6",
  "AekAds@24",
  {
    host: "35.209.89.182",
    dialect: "postgres",
  }
);

const checkRole = (allowedRoles) => {
  return (req, res, next) => {
    if (req.session.user && allowedRoles.includes(req.session.user.role)) {
      return next();
    } else {
      req.flash('error_msg', 'You do not have permission to access this page.');
      return res.redirect('/Dashboard');
    }
  };
};

// Define models
// const User = sequelize.define("User", {
//   name: DataTypes.STRING,
//   email: {
//     type: DataTypes.STRING,
//     allowNull: false,
//     unique: true,
//   },
//   password: {
//     type: DataTypes.STRING,
//     allowNull: false,
//   },
//   role: {
//     type: DataTypes.ENUM,
//     values: ["admin", "editor", "viewer","sales"],
//     allowNull: false,
//   },
// });


// Define models
const User1 = sequelize.define("User1", {
  name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  role: {
    type: DataTypes.ENUM,
    values: ["admin", "editor", "viewer", "sales"],
    allowNull: false,
  },
  permissions: {
    type: DataTypes.JSON, // Store permissions as JSON
    allowNull: true, // Can be null at registration, filled later
    defaultValue: [], // Initialize with an empty array
  },
});

const OTP = sequelize.define("OTP", {
  userId: {
    type: DataTypes.INTEGER,
    allowNull: false,
  },
  otp: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

const Log = sequelize.define("Log", {
  action: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  message: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  ip: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

const Log2 = sequelize.define("Log2", {
  action: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  message: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  ip: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});



const Customer = sequelize.define('Customer', {
  name: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  password: { type: DataTypes.STRING, allowNull: false },
  mobile_number: { type: DataTypes.STRING },
  start_date: { type: DataTypes.DATE },
  end_date: { type: DataTypes.DATE },
  invoices: { type: DataTypes.ARRAY(DataTypes.TEXT) },
}, {
  tableName: 'customers',
  timestamps: false,
});


const getClientIP = (req) => {
  if (!req) return 'Unknown IP';
  const forwarded = req.headers['x-forwarded-for'];
  return forwarded ? forwarded.split(',')[0] : req.ip;
};

const logAction = async (req, action, message, user) => {
  try {
    const ip = getClientIP(req);

    // Ensure user object is properly handled
    const userName = user && user.name ? user.name : '';
    const logMessage = `${userName} ${message}`;

    await Log.create({ action, message: logMessage, ip });
  } catch (error) {
    console.error('Error logging action:', error);
  }
};




const logAction2 = async (req, action, message) => {
  const ip = getClientIP(req);
  await Log2.create({ action, message, ip });
};


// Express middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));
app.use(session(sessionConfig));
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: false }));
app.use(flash());

app.use((req, res, next) => {
  res.locals.success_msg = req.flash("success_msg");
  res.locals.error_msg = req.flash("error_msg");
  res.locals.logAction = logAction;
  next();
});

// Routes
app.use("/Dashboard", dashboardRoutes.router);
app.use("/proposals", proposalSalesRoutes);

//suparadmin roll
app.use('/Supardashboard', suparAdminRoutes);
//salesadmin roll
app.use('/salesadmin', salesadmin);

//customer
// app.use('/customer',dashboardRoutes.isAuthenticated,  customerRoutes);
app.use('/customer',dashboardRoutes.isAuthenticated,  customerRoutes);
// app.use('/customer-screen',dashboardRoutes.isAuthenticated, customerScreenRoutes);
// Routes setup
const screenRoutes = require('./src/routes/customerscreen');      
app.use('/customer-screen',dashboardRoutes.isAuthenticated, screenRoutes);                                                                             
const customerPlaylist = require('./src/routes/customer-playlist');                                 
app.use('/customer-playlist',dashboardRoutes.isAuthenticated, customerPlaylist);

const customerlibrary = require('./src/routes/customerlibrary');

app.use('/customer-library',dashboardRoutes.isAuthenticated,  customerlibrary);    

//for society

const societyRouter = require("./src/routes/society_registerRoutes");
app.use("/society", societyRouter);



app.get("/", (req, res) => {
  res.render("Login", { message: null });
});

app.get("/alldata", api.getAllScreensAllData);
app.get("/livedata", api.getAllScreensAllData);

app.get("/alldata/:id", api.getScreenDataById); // Route to fetch a screen by IDs
// Middleware to check if user is 'admin' or 'editor'

app.get("/register", (req, res) => {
  res.render("register");
});


app.post("/register", async (req, res) => {
  const { name, email, password, role } = req.body;
  const permissions = req.body.permissions || {}; // Permissions from the form
  const allowedRoles = ["admin", "editor", "member", "sales"];

  // Check if the role is valid
  if (!allowedRoles.includes(role)) {
    req.flash("error_msg", "Invalid role selected.");
    return res.redirect("/register");
  }

  console.log("permissions", permissions);

  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user with permissions
    await User1.create({
      name, // Store name in the database
      email,
      password: hashedPassword,
      role,
      permissions: Object.keys(permissions).filter(action => permissions[action] === 'on') // Store only keys with 'on'
    });

    // Log action
    await logAction(req, "register", "User registered");

    res.redirect("/Dashboard/Teams/Addmember");
  } catch (error) {
    console.error(error);
    req.flash("error_msg", "There was an error registering the user.");
    res.redirect("/register");
  }
});










app.get('/login', (req, res) => {
  res.render('Login');
});


app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  let user;
  let userRole = null;
  let userTable = null;

  // Try to find the user in the Customer table first
  user = await Customer.findOne({ where: { email } });
  if (user) {
    userRole = 'customer';
    userTable = 'customer';
  } else {
    // If not found in Customer, check User1 table
    console.log('User not found in Customer table, checking User1 table...');
    user = await User1.findOne({ where: { email } });
    if (user) {
      userRole = user.role; // Get role from User1 table (e.g., 'sales', 'admin')
      userTable = 'user1';
    }
  }

  // If user exists, proceed with password verification
  if (user) {
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (isPasswordValid) {
      // Generate OTP and handle OTP logic
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      await OTP.create({ userId: user.id, otp });
      req.session.otp = otp;
      req.session.user = user;
      req.session.userRole = userRole;
      req.session.userTable = userTable;
      req.session.userId = user.id;  // Ensure userId is saved in session
      req.session.customer_id = user.customer_id || user.id;  
      console.log(`User role set to: ${userRole}`);
      console.log(`User table set to: ${userTable}`);

      // Setup Nodemailer and send OTP email
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: 'aekads.otp@gmail.com',
          pass: "nait yiag ebyg cxwk",
        },
      });

      const mailOptions = {
        from: 'aekads.otp@gmail.com',
        to: user.email,
        subject: 'Your login OTP Code',
        text: `Your login OTP code is ${otp}`,
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.log(error);
        } else {
          console.log('Email sent: ' + info.response);
        }
      });

      // Log the login action
      await logAction(req, 'login', 'User logged in', req.session.user || req.session.user.customer_id);
      res.redirect('/verify-otp');
    } else {
      req.flash('error_msg', 'Invalid email or password. Please check and try again.');
      console.log('Invalid password for user:', email);
      res.redirect('/');
    }
  } else {
    req.flash('error_msg', 'User not found. Please check the email and try again.');
    console.log('No user found with email:', email);
    res.redirect('/');
  }
});


app.get("/verify-otp", (req, res) => {
  res.render("verify-otp");
});

app.post('/verify-otp', async (req, res) => {
  const { otp } = req.body;
  const savedOtp = await OTP.findOne({
    where: { userId: req.session.user.id, otp },
  });

  if (savedOtp) {
    const otpCreationTime = savedOtp.createdAt;
    const currentTime = new Date();
    const timeDifference = (currentTime - otpCreationTime) / 1000; // Time difference in seconds

    if (timeDifference > 60) {
      await OTP.destroy({ where: { id: savedOtp.id } });
      req.flash('error_msg', 'OTP has expired. Please request a new one.');
      console.log('OTP expired');
      res.redirect('/verify-otp');
    } else {
      await OTP.destroy({ where: { id: savedOtp.id } });

      // Role-based redirection after successful OTP verification               
     // Role-based redirection after successful OTP verification
if (req.session.userRole === 'customer' && req.session.userTable === 'customer') {
  console.log('Redirecting to customer screen...');
  res.redirect('/customer-screen');
} else if (req.session.userRole === 'sales' && req.session.userTable === 'user1') {
  console.log('Redirecting to sales page...');
  res.redirect('/proposals');
} else if (req.session.userRole === 'suparAdmin') {
  console.log('Redirecting to suparAdmin dashboard...');
  res.redirect('/Supardashboard/Dashboard');
} else if (req.session.userRole === 'salesadmin') {
  console.log('Redirecting to salesadmin dashboard...');
  res.redirect('/salesadmin/acquisition');
}else if (['admin', 'editor', 'viewer'].includes(req.session.userRole)) {
  console.log('Redirecting to acquisition...');
  res.redirect('/dashboard');
} else {
  // Log unknown role or table error
  console.log('Unknown role or table. Role:', req.session.userRole, 'Table:', req.session.userTable);
  req.flash('error_msg', 'Invalid role or access level.');
  res.redirect('/');
}

    }
  } else {
    req.flash('error_msg', 'Invalid OTP. Please check and try again.');
    res.redirect('/verify-otp');
  }
});



app.post("/resend-otp", async (req, res) => {
  const user = req.session.user;
  if (user) {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.create({ userId: user.id, otp });

    let transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: "aekads.otp@gmail.com",
        pass: "nait yiag ebyg cxwk",
      },
    });

    let mailOptions = {
      from: "aekads.otp@gmail.com",
      to: user.email,
      subject: "Your login OTP Code",
      text: `Your login OTP code is ${otp}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
        res.json({ success: false });
      } else {
        console.log("Email sent: " + info.response);
        res.json({ success: true });
      }
    });
  } else {
    res.json({ success: false });  
  }
});


app.get('/customer-list', dashboardRoutes.isAuthenticated, async (req, res) => {                    
  try {
    const customers = await Customer.findAll();
    res.render('customer-list', { customers });
  } catch (error) {
    console.error("Error fetching customers:", error);
    res.status(500).send("Error retrieving customer data");
  }
});


// Function to fetch Cloudinary storage data
const getCloudinaryStorageData = async () => {
  try {
    const result = await cloudinary.api.usage();
    console.log("Cloudinary Storage Data:", result); // Debug log
    return result;
  } catch (error) {
    console.error("Error fetching Cloudinary storage data:", error);
  }
};

app.get("/api/cloudinary-storage", async (req, res) => {
  const data = await getCloudinaryStorageData();
  res.json(data);
});



app.get('/logout', async (req, res) => {
  if (req.session.user) {
    const userName = req.session.user.name || 'User';   
    const userId = req.session.user.id || req.session.customer_id || 'Unknown ID';
    
    // Log the logout action
    await logAction(req, 'logout', `${userName} is logout`, userId);

    console.log(`${userName} (ID: ${userId}) is logout`);
  }

  // Destroy the session and redirect
  req.session.destroy();
  res.redirect('/');
});



app.get("/Dashboard/logs", checkRole(['admin']),dashboardRoutes.isAuthenticated, async (req, res) => {
  try {
    const logs = await Log.findAll({
      order: [["createdAt", "DESC"]],
    });

    // Convert timestamps to IST
    const logsWithIST = logs.map((log) => ({
      ...log.dataValues,
      createdAt: moment(log.createdAt)
        .tz("Asia/Kolkata")
        .format("HH:mm:ss DD-MM-YYYY"),
    }));

    res.render("logs", { logs: logsWithIST });
  } catch (error) {
    console.error("Error fetching logs:", error);
    req.flash("error_msg", "Error fetching logs. Please try again.");
    res.redirect("/Dashboard");
  }
});



// Route to display all users
app.get("/admin/users",dashboardRoutes.isAuthenticated, async (req, res) => {

  try {
    const users = await User1.findAll();
    res.render("admin-users", { users });
  } catch (error) {
    console.error(error);
    req.flash("error_msg", "An error occurred while fetching users.");
    res.redirect("/");
  }
});

// Route to get the edit user form
app.get("/admin/users/:id/edit", async (req, res) => {
  const userId = req.params.id;

  try {
    const userToEdit = await User1.findOne({ where: { id: userId } });

    if (!userToEdit) {
      req.flash("error_msg", "User not found.");
      return res.redirect("/admin/users");
    }

    res.render("edit-user", { user: userToEdit });
  } catch (error) {
    console.error(error);
    req.flash("error_msg", "An error occurred while fetching the user.");
    res.redirect("/admin/users");
  }
});


// Route to update a user's profile
app.post("/admin/users/:id/edit", async (req, res) => {
  const {
      name,
      email,
      role,
      currentPassword,
      newPassword,
      confirmNewPassword,
      permissions, // Capture permissions from the form
  } = req.body;

  const userId = req.params.id;
  const allowedRoles = ["admin", "editor", "member", "sales"];

  // Validate role
  if (!allowedRoles.includes(role)) {
      req.flash("error_msg", "Invalid role selected.");
      return res.redirect(`/admin/users/${userId}/edit`);
  }

  try {
      const user = await User1.findOne({ where: { id: userId } });

      if (!user) {
          req.flash("error_msg", "User not found.");
          return res.redirect("/admin/users");
      }

      // Update user details
      user.name = name;
      user.email = email;
      user.role = role;

      // Capture permissions from the request body
      const permissionKeys = (permissions && typeof permissions === 'object')
          ? Object.keys(permissions).filter(action => permissions[action] === 'on')
          : [];
      
      user.permissions = permissionKeys; // Save permissions to the user object

      // Handle password updates
      if (currentPassword || newPassword || confirmNewPassword) {
          if (!currentPassword || !newPassword || !confirmNewPassword) {
              req.flash("error_msg", "Please fill in all password fields.");
              return res.redirect(`/admin/users/${userId}/edit`);
          }

          const passwordMatch = await bcrypt.compare(currentPassword, user.password);
          if (!passwordMatch) {
              req.flash("error_msg", "Current password is incorrect.");
              return res.redirect(`/admin/users/${userId}/edit`);
          }

          if (newPassword !== confirmNewPassword) {
              req.flash("error_msg", "New passwords do not match.");
              return res.redirect(`/admin/users/${userId}/edit`);
          }

          user.password = await bcrypt.hash(newPassword, 10); // Hash new password
      }

      // Save the updated user
      await user.save();
      await logAction(req, "Profile Edit", "User Profile edited");
      req.flash("success_msg", "User updated successfully.");
      res.redirect("/admin/users");
  } catch (error) {
      console.error(error);
      req.flash("error_msg", "An error occurred while updating the user.");
      res.redirect(`/admin/users/${userId}/edit`);
  }
});

// 

































// const fs = require('fs');
// const readline = require('readline');





// const { google } = require('googleapis');

// // If modifying the API's scope, update the scopes here.
// const SCOPES = ['https://www.googleapis.com/auth/drive.metadata.readonly'];
// const TOKEN_PATH = 'token.json';

// // Load client secrets from a local file.
// fs.readFile('credentials.json', (err, content) => {
//   if (err) return console.log('Error loading client secret file:', err);
//   authorize(JSON.parse(content), listFiles);
// });

// /**
//  * Authorize a client with the given credentials, then call the provided callback.
//  * @param {Object} credentials The authorization client credentials.
//  * @param {function} callback The callback to call with authorized client.
//  */
// function authorize(credentials, callback) {
//   const { client_secret, client_id, redirect_uris } = credentials.installed;
//   const oAuth2Client = new google.auth.OAuth2(
//     client_id, client_secret, redirect_uris[0]);

//   // Check if we have previously stored a token.
//   fs.readFile(TOKEN_PATH, (err, token) => {
//     if (err) return getNewToken(oAuth2Client, callback);
//     oAuth2Client.setCredentials(JSON.parse(token));
//     callback(oAuth2Client);
//   });
// }

// /**
//  * Get and store new token after prompting for user authorization.
//  * @param {google.auth.OAuth2} oAuth2Client The OAuth2 client to get token for.
//  * @param {function} callback The callback to call with the authorized client.
//  */
// function getNewToken(oAuth2Client, callback) {
//   const authUrl = oAuth2Client.generateAuthUrl({
//     access_type: 'offline',
//     scope: SCOPES,
//   });
//   console.log('Authorize this app by visiting this url:', authUrl);
//   const rl = readline.createInterface({
//     input: process.stdin,
//     output: process.stdout,
//   });
//   rl.question('Enter the code from that page here: ', (code) => {
//     rl.close();
//     oAuth2Client.getToken(code, (err, token) => {
//       if (err) return console.error('Error retrieving access token', err);
//       oAuth2Client.setCredentials(token);
//       // Store the token to disk for later use.
//       fs.writeFile(TOKEN_PATH, JSON.stringify(token), (err) => {
//         if (err) return console.error('Error storing the token', err);
//         console.log('Token stored to', TOKEN_PATH);
//       });
//       callback(oAuth2Client);
//     });
//   });
// }

// /**
//  * Lists the names and IDs of the first 10 files the user has access to.
//  * @param {google.auth.OAuth2} auth An authorized OAuth2 client.
//  */
// function listFiles(auth) {
//   const drive = google.drive({ version: 'v3', auth });
//   drive.files.list({
//     pageSize: 10,
//     fields: 'nextPageToken, files(id, name)',
//   }, (err, res) => {
//     if (err) return console.log('The API returned an error: ' + err);
//     const files = res.data.files;
//     if (files.length) {
//       console.log('Files:');
//       files.map((file) => {
//         console.log(`${file.name} (${file.id})`);
//       });
//     } else {
//       console.log('No files found.');
//     }
//   });
// }
























// Route to delete a user
app.post("/admin/users/:id/delete", async (req, res) => {
  const userId = req.params.id;

  try {
    const userToDelete = await User1.findOne({ where: { id: userId } });

    if (!userToDelete) {
      req.flash("error_msg", "User not found.");
      return res.redirect("/admin/users");
    }

    // Delete the user
    await userToDelete.destroy();
    req.flash("success_msg", "User deleted successfully.");
    await logAction(req, "Profile Delete", "User Profile deleted");
    await logAction2(req, "Profile Delete", "User Profile deleted");
    res.redirect("/admin/users");
  } catch (error) {
    console.error(error);
    req.flash("error_msg", "An error occurred while deleting the user.");
    res.redirect("/admin/users");
  }
});

app.get("/admin/logs", dashboardRoutes.isAuthenticated,async (req, res) => {
  try {
    const logs = await Log2.findAll({
      order: [["createdAt", "DESC"]],
    });

    // Convert timestamps to IST
    const logsWithIST = logs.map((log) => ({
      ...log.dataValues,
      createdAt: moment(log.createdAt)
        .tz("Asia/Kolkata")
        .format("HH:mm:ss DD-MM-YYYY"),
    }));

    res.render("log", { logs: logsWithIST });
  } catch (error) {
    console.error("Error fetching logs:", error);
    req.flash("error_msg", "Error fetching logs. Please try again.");
    res.redirect("/Dashboard");
  }
});

//device settind
app.get("/setting/:screenid",dashboardRoutes.isAuthenticated, async (req, res) => {
  try {
    const screenid = req.params.screenid;
    console.log('Type of screenid:', typeof screenid);

    // Fetch the screen data by screenid
    const screenData = await getScreenById(screenid);
    if (!screenData) {
      return res.status(404).send("Screen not found");
    }

    // Fetch the device config using screenid (which matches client_name)
    const deviceConfigData = await deviceConfig(screenid);
    const playlists = await viewPlaylist();

    // Prepare screen details with device config
    const screenDetails = {
      ...screenData,
      deviceConfig: deviceConfigData || {}, // Ensure it doesn't crash if no data found
      playlists: playlists,
    };
// console.log("screen config",screenDetails.deviceConfig);

    // Render the screen settings view and pass the data
    res.render("screensetting", { screen: screenDetails });
  } catch (err) {
    console.error("Error fetching screen settings:", err);
    res.status(500).send("Internal Server Error");
  }
});











// Function to fetch coordinates from the database
const getCoordinates = async () => {
  try {
    console.log('Fetching data coordinates from the database...');
    const result = await db.query('SELECT latitude, longitude, screenname FROM screens');
    // console.log('Data fetched successfully:', result.rows);
    return result.rows;
  } catch (err) {
    console.error('Error fetching coordinates:', err);
    return [];
  }
};

// API endpoint to send coordinates to frontend
app.get('/api/coordinates', async (req, res) => {
  try {
    console.log('API endpoint /api/coordinates called');
    const coordinates = await getCoordinates();
    // console.log('Sending data to the client:', coordinates);
    res.json(coordinates);
  } catch (error) {
    console.error('Error in /api/coordinates:', error);
    res.status(500).send('Error fetching coordinates');
  }
});


// Route of  Dashboard/chairman_apk

app.get("/Dashboard/chairman_apk", async (req, res) => {
  try {
    const query = `
      SELECT screenids,userid, username,slot9_url, slot10_url, slot9_status, slot10_status
      FROM public.auth
      WHERE slot9_status = 'pending' OR slot10_status = 'pending';
    `;
    const result = await db.query(query);
    res.render("chairman", { proposals: result.rows });
  } catch (err) {
    console.error("Error fetching data:", err);
    res.status(500).send("Internal Server Error");
  }
});
// Utility function to handle approval logic
async function handleApproval(screenid, slot, status) {
  const proposalColumn = slot === "slot9" ? "slot9_status" : "slot10_status";
  const slotColumn = `${slot}_url`;

  try {
    // Update the status in the `auth` table
    const updateProposalQuery = `
      UPDATE public.auth
      SET ${proposalColumn} = $1
      WHERE screenids @> $2::integer[];
    `; 
    await db.query(updateProposalQuery, [status, `{${screenid}}`]);

    if (status === "approve") {
      // Fetch the URL for the approved slot
      const fetchProposalQuery = `
        SELECT ${slotColumn}
        FROM public.auth
        WHERE screenids @> $1::integer[];
      `;
      const proposalResult = await db.query(fetchProposalQuery, [`{${screenid}}`]);

      if (proposalResult.rows.length > 0) {
        const slotUrl = proposalResult.rows[0][slotColumn];

        // Update the `screens` table with the fetched URL
        const updateScreensQuery = `
          UPDATE public.screens
          SET ${slotColumn} = $1
          WHERE screenid = $2;
        `;
        await db.query(updateScreensQuery, [slotUrl, screenid]);
      } else {
        throw new Error("No data found for the provided screenid.");
      }
    }
  } catch (error) {
    console.error("Error in handleApproval:", error);
    throw error;
  }
}

// POST /update-status
// Updated handler for status updates
// app.post("/update-status", async (req, res) => {
//   console.log("Request Body:", req.body);

//   const { screenid, slot, status } = req.body;

//   // Validate input
//   if (!screenid || !slot || !status) {
//     console.error("Invalid input: Missing screenid, slot, or status.");
//     return res.status(400).json({
//       success: false,
//       message: "Invalid input. Please provide screenid, slot, and status.",
//     });
//   }

//   try {
//     // Determine the columns to update based on the slot
//     const proposalColumn = slot === "slot9" ? "slot9_status" : slot === "slot10" ? "slot10_status" : null;
//     const screensColumn = slot === "slot9" ? "slot9" : slot === "slot10" ? "slot10" : null;
//     const urlColumn = slot === "slot9" ? "slot9_url" : slot === "slot10" ? "slot10_url" : null;

//     if (!proposalColumn || !screensColumn || !urlColumn) {
//       return res.status(400).json({
//         success: false,
//         message: "Invalid slot specified. Allowed values: slot9, slot10.",
//       });
//     }

//     // Parse screenid into an array of integers
//     const screenidArray = screenid.split(",").map((id) => parseInt(id.trim(), 10));

//     // Update the `auth` table with the status
//     const updateProposalQuery = `
//       UPDATE public.auth
//       SET ${proposalColumn} = $1
//       WHERE screenids::integer[] @> $2::integer[];
//     `;
//     await db.query(updateProposalQuery, [status, screenidArray]);

//     if (status === "approve") {
//       // Fetch the slot URL from `auth` table
//       const fetchProposalQuery = `
//         SELECT ${urlColumn} AS slot_url
//         FROM public.auth
//         WHERE screenids::integer[] @> $1::integer[];
//       `;
//       const proposalResult = await db.query(fetchProposalQuery, [screenidArray]);

//       if (proposalResult.rows.length === 0) {
//         console.error("No data found for the provided screenid.");
//         return res.status(404).json({
//           success: false,
//           message: "Screen ID not found.",
//         });
//       }

//       const slotValue = proposalResult.rows[0].slot_url;

//       // Update the `screens` table
//       const updateScreensQuery = `
//         UPDATE public.screens
//         SET ${screensColumn} = $1
//         WHERE screenid = ANY($2);
//       `;
//       await db.query(updateScreensQuery, [slotValue, screenidArray]);
//     }

//     res.redirect("/Dashboard/chairman_apk");
//   } catch (err) {
//     console.error("Error updating status:", err);
//     res.status(500).json({ success: false, message: "Internal Server Error" });
//   }
// });




const admin = require("firebase-admin");
const serviceAccount = require("./src/config/serviceAccountKey.json"); // Path to your service account key

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

app.post("/update-status", async (req, res) => {
  console.log("Request Body:", req.body);

  const { screenid, slot, status } = req.body;

  // Validate input
  if (!screenid || !slot || !status) {
    console.error("Invalid input: Missing screenid, slot, or status.");
    return res.status(400).json({
      success: false,
      message: "Invalid input. Please provide screenid, slot, and status.",
    });
  }

  try {
    // Map slot to column names
    const slotMapping = {
      slot9: { proposalColumn: "slot9_status", screensColumn: "slot9", urlColumn: "slot9_url" },
      slot10: { proposalColumn: "slot10_status", screensColumn: "slot10", urlColumn: "slot10_url" },
    };

    const { proposalColumn, screensColumn, urlColumn } = slotMapping[slot] || {};
    if (!proposalColumn || !screensColumn || !urlColumn) {
      return res.status(400).json({
        success: false,
        message: "Invalid slot specified. Allowed values: slot9, slot10.",
      });
    }

    // Parse screenid into an array
    const screenidArray = screenid.split(",").map((id) => parseInt(id.trim(), 10));

    // Update the `auth` table
    const updateProposalQuery = `
      UPDATE public.auth
      SET ${proposalColumn} = $1
      WHERE screenids::integer[] @> $2::integer[];
    `;
    await db.query(updateProposalQuery, [status, screenidArray]);

    // Fetch slot URL if approved/rejected
    if (status === "approved" || status === "reject") {
      const fetchProposalQuery = `
        SELECT ${urlColumn} AS slot_url
        FROM public.auth
        WHERE screenids::integer[] @> $1::integer[];
      `;
      const proposalResult = await db.query(fetchProposalQuery, [screenidArray]);
      if (proposalResult.rows.length === 0) {
        console.error("No data found for the provided screenid.");
        return res.status(404).json({
          success: false,
          message: "Screen ID not found.",
        });
      }

      const slotValue = proposalResult.rows[0].slot_url;

      // Fetch FCM token
      const fetchTokenQuery = `SELECT device_token FROM public.auth WHERE ${urlColumn} = $1;`;
      const tokenResult = await db.query(fetchTokenQuery, [slotValue]);
      if (tokenResult.rows.length === 0) {
        console.error("No FCM token found for the provided URL.");
        return res.status(404).json({
          success: false,
          message: "FCM token not found.",
        });
      }

      const fcmToken = tokenResult.rows[0].device_token;

      // Update the `screens` table
      const updateScreensQuery = `
        UPDATE public.screens
        SET ${screensColumn} = $1
        WHERE screenid = ANY($2);
      `;
      await db.query(updateScreensQuery, [slotValue, screenidArray]);

      // Send FCM notification
      await sendNotification(fcmToken, slot, status);
    }

    res.redirect("/Dashboard/chairman_apk");
  } catch (err) {
    console.error("Error updating status:", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

// Helper function for sending FCM notifications
async function sendNotification(fcmToken, slot, status) {
  try {
    const slotLabel = slot === "slot9" ? "Creative 1" : slot === "slot10" ? "Creative 2" : "Unknown Slot";
    const notificationTitle = status === "approved" ? "Creative Approved" : "Creative Rejected";
    const notificationBody =
      status === "approved"
        ? `Your ${slotLabel} has been approved. Visit the App for more details.`
        : `Your ${slotLabel} has been rejected. Please check the App for more information.`;

    const message = {
      notification: { title: notificationTitle, body: notificationBody },
      data: { title: notificationTitle, body: notificationBody },
      token: fcmToken,
    };

    const response = await admin.messaging().send(message);
    console.log("Notification sent successfully:", response);
  } catch (err) {
    console.error("Error sending notification:", err);
  }
}

// const puppeteer = require('puppeteer');
// const imaps = require('imap-simple');

// async function readOTPFromEmailsales() {
//   const config = {
//     imap: {
//       user: 'aekads.otp@gmail.com',
//       password: 'nait yiag ebyg cxwk',
//       host: 'imap.gmail.com',
//       port: 993,
//       tls: true,
//       tlsOptions: { rejectUnauthorized: false },
//       authTimeout: 3000,
//     },
//   };

//   try {
//     const connection = await imaps.connect(config);
//     await connection.openBox('INBOX');

//     const searchCriteria = ['UNSEEN'];
//     const fetchOptions = { bodies: ['TEXT'], markSeen: true };
//     const messages = await connection.search(searchCriteria, fetchOptions);

//     for (let message of messages) {
//       const parts = message.parts.find(part => part.which === 'TEXT');
//       const body = parts.body;

//       const otpMatch = body.match(/Your login OTP code is (\d{6})/);
//       if (otpMatch) {
//         const messageId = message.attributes.uid;
//         await connection.addFlags(messageId, ['\\Seen']);
//         await connection.addFlags(messageId, ['\\Deleted']);

//         connection.end();
//         return otpMatch[1];
//       }
//     }

//     connection.end();
//     throw new Error('No OTP found in unread emails.');
//   } catch (error) {
//     console.error('Error reading email:', error);
//     throw error;
//   }
// }

// async function dhvanilsales() {
//   try {
//     const browser = await puppeteer.launch({
//       headless: false,
//       args: ['--start-fullscreen'], // Launch Chrome in full screen mode
//     });
//     const page = await browser.newPage();

//     // Set the viewport to maximize
//     const dimensions = await page.evaluate(() => {
//       return {
//         width: window.screen.availWidth,
//         height: window.screen.availHeight,
//       };
//     });
//     await page.setViewport(dimensions);

//     // Navigate to the login page
//     // await page.goto('https://cms.aekads.com/', { waitUntil: 'domcontentloaded' });
//     await page.goto('http://localhost:3000/', { waitUntil: 'domcontentloaded' });

//     console.log('Login page loaded.');

//     // Enter login credentials
//     await page.waitForSelector('#email');
//     await page.type('#email', 'aekads.otp@gmail.com');

//     await page.waitForSelector('#password');
//     await page.type('#password', 'dhvanil');

//     // Click the login button
//     await page.waitForSelector('button[type="submit"]');
//     await page.click('button[type="submit"]');
//     console.log('Login form submitted.');

//     // Wait for the OTP page to load
//     await page.waitForSelector('#otp');
//     console.log('Waiting for OTP...');

//     // Read OTP from email
//     const otp = await readOTPFromEmailsales();
//     console.log('OTP received:', otp);

//     // Enter the OTP
//     await page.type('#otp', otp);

//     // Submit the OTP form
//     await page.waitForSelector('button[type="submit"]');
//     await page.click('button[type="submit"]');
//     console.log('OTP submitted successfully.');

//     // Do not close the browser
//     console.log('Browser remains open. You can inspect the page.');
//   } catch (error) {
//     console.error('An error occurred during login automation:', error);
//   }
// }


// async function readOTPFromEmailadmin() {
//   const config = {
//     imap: {
//       user: 'pateldhvanil341@gmail.com',
//       password: 'evap zwkq vrxn wzlg',
//       host: 'imap.gmail.com',
//       port: 993,
//       tls: true,
//       tlsOptions: { rejectUnauthorized: false },
//       authTimeout: 3000,
//     },
//   };

//   try {
//     const connection = await imaps.connect(config);
//     await connection.openBox('INBOX');

//     const searchCriteria = ['UNSEEN'];
//     const fetchOptions = { bodies: ['TEXT'], markSeen: true };
//     const messages = await connection.search(searchCriteria, fetchOptions);

//     for (let message of messages) {
//       const parts = message.parts.find(part => part.which === 'TEXT');
//       const body = parts.body;

//       const otpMatch = body.match(/Your login OTP code is (\d{6})/);
//       if (otpMatch) {
//         const messageId = message.attributes.uid;
//         await connection.addFlags(messageId, ['\\Seen']);
//         await connection.addFlags(messageId, ['\\Deleted']);

//         connection.end();
//         return otpMatch[1];
//       }
//     }

//     connection.end();
//     throw new Error('No OTP found in unread emails.');
//   } catch (error) {
//     console.error('Error reading email:', error);
//     throw error;
//   }
// }

// // async function dhvaniladmin() {
// //   try {
// //     const browser = await puppeteer.launch({
// //       headless: false,
// //       args: ['--start-fullscreen'], // Launch Chrome in full screen mode
// //     });
// //     const page = await browser.newPage();

// //     // Set the viewport to maximize
// //     const dimensions = await page.evaluate(() => {
// //       return {
// //         width: window.screen.availWidth,
// //         height: window.screen.availHeight,
// //       };
// //     });
// //     await page.setViewport(dimensions);

// //     // Navigate to the login page
// //     // await page.goto('https://cms.aekads.com/', { waitUntil: 'domcontentloaded' });
// //     await page.goto('http://localhost:3000/', { waitUntil: 'domcontentloaded' });

// //     console.log('Login page loaded.');

// //     // Enter login credentials
// //     await page.waitForSelector('#email');
// //     await page.type('#email', 'pateldhvanil341@gmail.com');

// //     await page.waitForSelector('#password');
// //     await page.type('#password', '123456');

// //     // Click the login button
// //     await page.waitForSelector('button[type="submit"]');
// //     await page.click('button[type="submit"]');
// //     console.log('Login form submitted.');

// //     // Wait for the OTP page to load
// //     await page.waitForSelector('#otp');
// //     console.log('Waiting for OTP...');

// //     // Read OTP from email
// //     const otp = await readOTPFromEmailadmin();
// //     console.log('OTP received:', otp);

// //     // Enter the OTP
// //     await page.type('#otp', otp);

// //     // Submit the OTP form
// //     await page.waitForSelector('button[type="submit"]');
// //     await page.click('button[type="submit"]');
// //     console.log('OTP submitted successfully.');

// //     // Do not close the browser
// //     console.log('Browser remains open. You can inspect the page.');
// //   } catch (error) {
// //     console.error('An error occurred during login automation:', error);
// //   }
// // }


// async function delay(ms) {
//   return new Promise(resolve => setTimeout(resolve, ms));
// }

// async function dhvaniladmin() {
//   try {
//     const browser = await puppeteer.launch({
//       headless: false,
//       args: ['--start-fullscreen'], // Launch Chrome in full screen mode
//     });
//     const page = await browser.newPage();

//     // Set the viewport to maximize
//     const dimensions = await page.evaluate(() => {
//       return {
//         width: window.screen.availWidth,
//         height: window.screen.availHeight,
//       };
//     });
//     await page.setViewport(dimensions);

//     // Navigate to the login page
//     await page.goto('http://localhost:3000/', { waitUntil: 'domcontentloaded' });
//     console.log('Login page loaded.');

//     // Enter login credentials
//     await page.waitForSelector('#email');
//     await page.type('#email', 'pateldhvanil341@gmail.com');

//     await page.waitForSelector('#password');
//     await page.type('#password', '123456');

//     // Click the login button
//     await page.waitForSelector('button[type="submit"]');
//     await page.click('button[type="submit"]');
//     console.log('Login form submitted.');

//     // Wait for the OTP page to load
//     await page.waitForSelector('#otp');
//     console.log('Waiting for OTP...');

//     // Introduce a 15-second delay
//     await delay(15000);

//     // Read OTP from email
//     const otp = await readOTPFromEmailadmin();
//     console.log('OTP received:', otp);

//     // Enter the OTP
//     await page.type('#otp', otp);

//     // Submit the OTP form
//     await page.waitForSelector('button[type="submit"]');
//     await page.click('button[type="submit"]');
//     console.log('OTP submitted successfully.');

//     // Do not close the browser
//     console.log('Browser remains open. You can inspect the page.');
//   } catch (error) {
//     console.error('An error occurred during login automation:', error);
//   }
// }





// app.get('/session-data', (req, res) => {
//   res.json({ user: req.session.user });
// });











// // Sync database and start server
// sequelize.sync().then(() => {
//   app.listen(3000, async () => { // Ensure the function is async
//     console.log("Server is running on port 3000");
//     console.log('Starting login automation...');

//     try {
//       // Call the asynchronous automation functions and wait for them to complete
//       await dhvanilsales();
//       await dhvaniladmin();
//       console.log('Automation complete.');
//     } catch (error) {
//       console.error('Automation failed:', error);
//     }
//   });
// }).catch(error => {
//   console.error('Failed to sync Sequelize:', error);
// });






app.get('/session-data', (req, res) => {
  res.json({ user: req.session.user });
});



// Sync database and start server
sequelize.sync().then(() => {
  app.listen(3000, () => {
    console.log('Server is running on port 3000');
  });
});
 