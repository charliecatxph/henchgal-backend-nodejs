require("dotenv").config();

const express = require("express");
const app = express();

const cors = require("cors");

const momentTZ = require("moment-timezone");

const jwt = require("jsonwebtoken");

const crypto = require("crypto");

const bcrypt = require("bcrypt");
const saltRounds = 10;

const multer = require("multer");

const bodyParser = require("body-parser");

const admin = require("firebase-admin");
const { v4: uuidv4 } = require("uuid");

const fs = require("fs");

let db;
let firestorage;

const connectToDb = () => {
  admin.initializeApp({
    credential: admin.credential.cert(JSON.parse(process.env.serv)
    ),
    storageBucket: process.env.storageBucket,
  });

  db = admin.firestore();
  firestorage = admin.storage().bucket();
};

const connectToDbStat = true;

const hashPw = async (pw) => {
  try {
    return await bcrypt.hash(pw, saltRounds);
  } catch (e) {
    throw e;
  }
};
const disableCrypto = false;
const jwtSecret = crypto.randomBytes(32).toString("base64");

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

const verifyToken = (req, res, next) => {
  // Get the token from the request headers or query parameters or cookies, etc.

  const token = req.headers.authorization || "";

  if (!token) {
    // Token is missing
    return res.status(401).json({ error: "Unauthorized - Token is missing" });
  }
  const tok = token.split(" ")[1];

  try {
    // Verify the token using your secret key
    const decoded = jwt.verify(tok, jwtSecret);

    // Attach the decoded user information to the request object
    req.user = decoded;

    // Continue to the next middleware or route handler
    next();
  } catch (err) {
    // Token is invalid
    return res.status(401).json({ error: "Unauthorized - Invalid token" });
  }
};

app.use(express.json());
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);
app.use(cors());

app.post("/api/delete-user", verifyToken, (req, res) => {
  const { uid } = req.body;
  const role = req.user.data.role;

  if (!role || !uid) {
    res.status(400).send("Incomplete parameters.");
    return;
  }

  if (role !== "admin") {
    res.status(401).send("Unauthorized. - Role not met.");
    return;
  }

  if (connectToDbStat) {
    db.collection("hnch-users")
      .doc(uid)
      .delete()
      .then((d) => {
        res.status(200).send("Account terminated.");
      })
      .catch((e) => {
        res.status(400).send("Account fail to terminate.");
      });
  } else {
    res.status(404).send("Database is turned off.");
    return;
  }
});

app.put("/api/verify-user", verifyToken, (req, res) => {
  const { uid } = req.body;
  const role = req.user.data.role;

  if (!role || !uid) {
    res.status(400).send("Incomplete parameters.");
    return;
  }

  if (role !== "admin") {
    res.status(401).send("Unauthorized. - Role not met.");
    return;
  }

  if (connectToDbStat) {
    db.collection("hnch-users")
      .doc(uid)
      .update({ status: "verified" })
      .then((d) => {
        res.status(200).send("User has been verified.");
      })
      .catch((e) => {
        res.status(400).send("Fail to verify user.");
      });
  } else {
    res.status(404).send("Database is turned off.");
    return;
  }
});

app.post("/api/fetch-users", verifyToken, (req, res) => {
  const { email } = req.body;
  const role = req.user.data.role;

  if (!role || !email) {
    res.status(400).send("Incomplete parameters.");
    return;
  }

  if (role !== "admin") {
    res.status(401).send("Unauthorized. - Role not met.");
    return;
  }

  if (connectToDbStat) {
    db.collection("hnch-users")
      .where("email", "!=", email)
      .get()
      .then((rs) => {
        if (rs.size === 0) {
          res.status(400).send("There are no users.");
          return;
        }
        let obj = [];
        rs.forEach((usr) => {
          let temp = usr.data();
          temp.id = usr.id;
          obj.push(temp);
        });
        res.status(200).json(obj);
      })
      .catch((e) => {
        res.status(400).send("Database error.");
        return;
      });
  } else {
    res.status(404).send("Database is turned off.");
    return;
  }
});

app.post("/api/register", async (req, res) => {
  let data = req.body;
  Object.keys(data).map((d) => {
    if (d === "pw") return;
    data[d] = data[d].trim().toLowerCase();
  });

  const hashedPw = await hashPw(data.pw);

  if (connectToDbStat) {
    try {
      const query = await db
        .collection("hnch-users")
        .where("email", "==", data.email)
        .get();
      if (!query.empty) {
        res.status(409).send("User already exists.");
      } else {
        return db
          .collection("hnch-users")
          .add({
            fn: data.fn,
            mn: data.mn,
            ln: data.ln,
            email: data.email,
            pw: hashedPw,
            addr: data.addr,
            pfp_link: "",
            desc: "",
            role: "employee",
            status: "unverified",
            date_joined: momentTZ().tz("Asia/Manila").format(),
          })
          .then((d) => {
            res.status(200).send(`Data has been uploaded to server.`);
          })
          .catch((e) => {
            res.status(500).send("Data failed to upload.");
          });
      }
    } catch (e) {
      res.status(500).send("Can't connect to database.");
    }
  } else {
    return 0;
  }
});

app.post("/api/login", async (req, res) => {
  let data = req.body;
  Object.keys(data).map((d) => {
    data[d] = data[d].trim();
  });

  if (connectToDbStat) {
    try {
      const query = await db
        .collection("hnch-users")
        .where("email", "==", data.email)
        .where("status", "==", "verified")
        .get();
      if (!query.empty) {
        query.forEach((d) => {
          const verify = bcrypt.compare(data.pw, d.data().pw);
          verify.then((dx) => {
            if (dx) {
              jwt.sign(
                {
                  data: d.data(),
                },
                jwtSecret,
                { expiresIn: "7d" },
                (e, t) => {
                  if (e) res.send(e);
                  let decode = jwt.decode(t).data;
                  res.json({
                    fn: decode.fn,
                    mn: decode.mn,
                    ln: decode.ln,
                    addr: decode.addr,
                    email: decode.email,
                    desc: decode.desc,
                    unq_user_id: d.id,
                    token: t,
                    role: decode.role,
                  });
                }
              );
            } else {
              res.status(401).send("Wrong password.");
            }
          });
        });
      } else {
        return res.status(404).send("User doesn't exist.");
      }
    } catch (e) {
      console.log(e)
      res.status(500).send("Can't connect to database.");
    }
  } else {
    return 0;
  }
});

app.post(
  "/api/upload-report/:operation",
  verifyToken,
  upload.array("rp_imgs"),
  async (req, res) => {
    const {
      amt_rcv,
      rcv_when,
      rcv_loc,
      purpose,
      description,
      uid,
      fn,
      mn,
      ln,
      totalExp,
      balance,
    } = req.body;
    const { operation } = req.params;
    let images = req.files;
    if (
      !amt_rcv ||
      !rcv_when ||
      !rcv_loc ||
      !purpose ||
      !images ||
      !uid ||
      !fn ||
      !mn ||
      !ln ||
      !totalExp ||
      !balance ||
      !operation
    ) {
      res.status(400).send("Incomplete parameters.");
      return;
    }

    if (connectToDbStat) {
      images.forEach((dxx) => {
        dxx.originalname = uuidv4();
      });

      try {
        let uploadPromises = [];

        images.forEach((image) => {
          const fileBuffer = image.buffer;
          const destination = `hnch-images/${image.originalname}`;

          const uploadPromise = firestorage.file(destination).save(fileBuffer, {
            metadata: {
              contentType: image.mimetype,
            },
          });
          uploadPromises.push(uploadPromise);
        });

        Promise.all(uploadPromises).then((d) => {
          const dL = images.map(async (dx) => {
            const destination = `hnch-images/${dx.originalname}`;
            let exp = new Date();
            exp.setMonth(exp.getMonth() + 2);
            return await firestorage
              .file(destination)
              .getSignedUrl({
                action: "read",
                expires: exp.toISOString(),
              })
              .then((d) => {
                return {
                  download_link: d[0],
                  img_name: dx.originalname,
                  mime_type: dx.mimetype,
                };
              })
              .catch((e) => {
                return;
              });
          });
          Promise.all(dL).then((ddx) => {
            let forDb = {
              amt_rcv: Number(amt_rcv),
              rcv_when,
              rcv_loc,
              description: description || "",
              purpose,
              balance,
              total_exp: totalExp,
              opr: operation,
              publish_date:
                operation === "publish" ? momentTZ().tz("Asia/Manila") : "",
              last_modified: momentTZ().tz("Asia/Manila"),
              reimbursement: {
                status: balance < 0 ? true : false,
                amount: balance < 0 ? balance : 0,
                notice: {
                  status: false,
                  admin_fn: "",
                  admin_mn: "",
                  admin_ln: "",
                  uploaded_on: "",
                  description: "",
                },
              },
              reporter: {
                uid,
                fn,
                mn,
                ln,
              },
              attachments: ddx,
            };
            db.collection("hnch-reports")
              .add(forDb)
              .then((d) => {
                res.status(200).json({
                  rp_id: d.id,
                  message: "Report has been uploaded.",
                });
              })
              .catch((e) => {
                res.status(400).send("Report fail to upload.");
              });
          });
        });
      } catch (error) {
        res.status(500).send("Internal Server Error");
      }
    } else {
      res.status(404).send("Database is turned off.");
      return;
    }
  }
);

app.post("/api/modify-attachment-links", verifyToken, (req, res) => {
  const { rp_id, deleteX, writeX } = req.body;

  if (!rp_id || !deleteX || !writeX) {
    res.status(400).send("Incomplete parameters.");
    return;
  }

  if (connectToDbStat) {
    const deleteOperations = [];
    deleteX.forEach((img) => {
      const operation = firestorage
        .file(`hnch-images/${img.img_name}`)
        .delete();
      deleteOperations.push(operation);
    });

    Promise.all(deleteOperations)
      .then((d) => {
        db.collection("hnch-reports")
          .doc(rp_id)
          .update({
            attachments: writeX,
            last_modified: momentTZ().tz("Asia/Manila"),
          })
          .then((d) => {
            res.status(200).send("Attachments updated.");
          })
          .catch((e) => {
            res.status(400).send("Attachments fail to update.");
          });
      })
      .catch((e) => {
        res.status(400).send("Error in updating attachments.");
      });
  } else {
    res.status(404).send("Database is turned off.");
    return;
  }
});
//   const { operation } = req.params;
//   const {
//     amt_rcv,
//     rcv_when,
//     rcv_loc,
//     purpose,
//     transactions,
//     description,
//     uid,
//     fn,
//     mn,
//     ln,
//   } = req.body;
//   if (operation !== "draft" && operation !== "publish") {
//     res.status(400).send("Invalid operation.");
//     return;
//   }
//   if (
//     !amt_rcv ||
//     !rcv_when ||
//     !rcv_loc ||
//     !purpose ||
//     !transactions ||
//     !uid ||
//     !fn ||
//     !mn ||
//     !ln
//   ) {
//     res.status(400).send("Incomplete parameters.");
//     return;
//   }

//   if (connectToDbStat) {
//     const totalExp = transactions.reduce((acc, curr) => {
//       return acc + Number(curr.exp_amt);
//     }, 0);
//     const balance = Number(amt_rcv) - totalExp;
//     const transactions_obj = transactions
//       .slice()
//       .sort((a, b) => new Date(b.exp_dt) - new Date(a.exp_dt));

//     let forDb = {
//       amt_rcv: Number(amt_rcv),
//       rcv_when,
//       rcv_loc,
//       description: description || "",
//       total_exp: totalExp,
//       balance,
//       purpose,
//       reimbursement: {
//         status: balance < 0 ? true : false,
//         amount: balance < 0 ? balance : 0,
//         notice: {
//           status: false,
//           admin_fn: "",
//           admin_mn: "",
//           admin_ln: "",
//           uploaded_on: "",
//           description: "",
//         },
//       },
//       opr: operation,

//       reporter: {
//         uid,
//         fn,
//         mn,
//         ln,
//       },
//     };
//     db.collection("hnch-reports")
//       .add(forDb)
//       .then((d) => {
//         db.collection("hnch-transactions")
//           .add({
//             report_id: d.id,
//             transactions: transactions_obj,
//             reporter: {
//               uid,
//               fn,
//               mn,
//               ln,
//             },
//           })
//           .then((d) => {
//             res
//               .status(200)
//               .send(
//                 operation === "draft"
//                   ? "Report uploaded as draft."
//                   : "Report published."
//               );
//           })
//           .catch((e) => {
//             res.status(400).send("Report upload fail.");
//           });
//       })
//       .catch((e) => {
//         res.status(400).send("Report upload fail.");
//       });
//     return;
//   } else {
//     res.status(404).send("Database is turned off.");
//     return;
//   }
// });

app.post("/api/upload-transactions", verifyToken, (req, res) => {
  const { payload } = req.body;

  if (!payload) {
    res.status(400).send("Incomplete parameters.");
    return;
  }

  if (connectToDbStat) {
    db.collection("hnch-transactions")
      .add(payload)
      .then((d) => {
        res.status(200).send("Transactions has been uploaded.");
      })
      .catch((e) => {
        res.status(400).send("Fail to upload transactions.");
      });
  } else {
    res.status(404).send("Database is turned off.");
    return;
  }
});

app.post("/api/modify-transactions", verifyToken, (req, res) => {
  const { tr_id, newTrans } = req.body;

  if (!tr_id || !newTrans) {
    res.status(400).send("Incomplete parameters.");
    return;
  }

  if (connectToDbStat) {
    db.collection("hnch-transactions")
      .doc(tr_id)
      .update({
        transactions: newTrans,
      })
      .then((d) => {
        res.status(200).send("Transactions has been uploaded.");
        return;
      })
      .catch((e) => {
        res.status(400).send("Fail to upload transactions.");
      });
  } else {
    res.status(404).send("Database is turned off.");
    return;
  }
});

app.post("/api/fetch-reports/:type", verifyToken, (req, res) => {
  const { type } = req.params;
  const { uid } = req.body;

  if (!type || !uid) {
    res.status(400).send("Incomplete parameters.");
    return;
  }

  if (connectToDbStat) {
    const query = db
      .collection("hnch-reports")
      .where("reporter.uid", "==", uid)
      .where("opr", "==", type);
    query
      .get()
      .then((report) => {
        let data = [];
        report.forEach((rp) => {
          let obj = rp.data();
          obj.rp_id = rp.id;
          data.push(obj);
        });

        res.status(200).json(data);
      })
      .catch((error) => {
        res.status(400).send("Error getting documents.");
      });
  } else {
    res.status(404).send("Database is turned off.");
    return;
  }
});

app.post("/api/fetch-transactions", verifyToken, (req, res) => {
  const { rp_id, uid, mode } = req.body;
  const role = req.user.data.role;

  if (!mode) {
    res.status(400).send("Incomplete parameters.");
    return;
  }

  if (connectToDbStat) {
    if (mode === "partial") {
      if (!rp_id) {
        res.status(400).send("Incomplete parameters.");
        return;
      }
      const query = db
        .collection("hnch-transactions")
        .where("report_id", "==", rp_id);
      query
        .get()
        .then((transactions) => {
          let data = [];
          transactions.forEach((tr) => {
            let obj = tr.data();
            obj.tr_id = tr.id;
            data.push(obj);
          });

          res.status(200).json(data);
        })
        .catch((error) => {
          res.status(400).send("Error getting documents.");
        });
    } else {
      if (!role || !uid) {
        res.status(400).send("Incomplete parameters.");
        return;
      }

      if (role === "admin") {
        db.collection("hnch-transactions")
          .get()
          .then((d) => {
            const obj = [];
            d.forEach((dd) => {
              obj.push(dd.data());
            });
            const allTransactions = obj.flatMap((item) => {
              const reporterInfo = item.reporter;
              return item.transactions.map((transaction) => ({
                ...transaction,
                ...reporterInfo,
                report_id: item.report_id,
              }));
            });

            // Sorting all transactions by exp_date in descending order
            const sorted = allTransactions.sort(
              (a, b) => new Date(b.exp_dt) - new Date(a.exp_dt)
            );

            res.status(200).json(sorted);
          })
          .catch((e) => {});
      } else {
        db.collection("hnch-transactions")
          .where("reporter.uid", "==", uid)
          .get()
          .then((d) => {
            const obj = [];
            d.forEach((dd) => {
              obj.push(dd.data());
            });
            const allTransactions = obj.flatMap((item) => {
              const reporterInfo = item.reporter;

              return item.transactions.map((transaction) => ({
                ...transaction,
                ...reporterInfo,
                report_id: item.report_id,
              }));
            });
            // Sorting all transactions by exp_date in descending order
            const sorted = allTransactions.sort(
              (a, b) => new Date(b.exp_dt) - new Date(a.exp_dt)
            );

            res.status(200).json(sorted);
          })
          .catch((e) => {});
      }
    }
  } else {
    res.status(404).send("Database is turned off.");
    return;
  }
});

app.put(
  "/api/edit-report/:operation",
  verifyToken,
  upload.array("rp_imgs"),
  (req, res) => {
    const { operation } = req.params;
    const {
      amt_rcv,
      rcv_when,
      rcv_loc,
      purpose,
      description,
      uid,
      fn,
      mn,
      ln,
      rp_id,
      balance,
      totalExp,
    } = req.body;
    let images = req.files;

    if (operation !== "draft" && operation !== "publish") {
      res.status(400).send("Invalid operation.");
      return;
    }
    if (
      !amt_rcv ||
      !rcv_when ||
      !rcv_loc ||
      !purpose ||
      !uid ||
      !fn ||
      !mn ||
      !ln ||
      !balance ||
      !totalExp
    ) {
      res.status(400).send("Incomplete parameters.");
      return;
    }

    if (connectToDbStat) {
      images.forEach((dxx) => {
        dxx.originalname = uuidv4();
      });

      try {
        let uploadPromises = [];

        images.forEach((image) => {
          const fileBuffer = image.buffer;
          const destination = `hnch-images/${image.originalname}`;

          const uploadPromise = firestorage.file(destination).save(fileBuffer, {
            metadata: {
              contentType: image.mimetype,
            },
          });
          uploadPromises.push(uploadPromise);
        });

        Promise.all(uploadPromises).then((d) => {
          const dL = images.map(async (dx) => {
            const destination = `hnch-images/${dx.originalname}`;
            let exp = new Date();
            exp.setMonth(exp.getMonth() + 2);
            return await firestorage
              .file(destination)
              .getSignedUrl({
                action: "read",
                expires: exp.toISOString(),
              })
              .then((d) => {
                return {
                  download_link: d[0],
                  img_name: dx.originalname,
                  mime_type: dx.mimetype,
                };
              })
              .catch((e) => {
                return;
              });
          });
          Promise.all(dL).then((ddx) => {
            let forDb = {
              amt_rcv: Number(amt_rcv),
              rcv_when,
              rcv_loc,
              description: description || "",
              purpose,
              balance,
              total_exp: totalExp,
              opr: operation,
              publish_date:
                operation === "publish" ? momentTZ().tz("Asia/Manila") : "",
              last_modified: momentTZ().tz("Asia/Manila"),
              reimbursement: {
                status: balance < 0 ? true : false,
                amount: balance < 0 ? balance : 0,
                notice: {
                  status: false,
                  admin_fn: "",
                  admin_mn: "",
                  admin_ln: "",
                  uploaded_on: "",
                  description: "",
                },
              },
              reporter: {
                uid,
                fn,
                mn,
                ln,
              },
              attachments: ddx,
            };
            db.collection("hnch-reports")
              .doc(rp_id)
              .get()
              .then((d) => {
                if (!d.exists) {
                  res.status(400).send("Report doesn't exist.");
                  return;
                }
                db.collection("hnch-reports")
                  .doc(rp_id)
                  .update({
                    ...forDb,
                    attachments: [...d.data().attachments, ...ddx],
                  })
                  .then((d) => {
                    res.status(200).json({
                      rp_id: rp_id,
                      message: "Report has been updated.",
                    });
                  })
                  .catch((e) => {
                    res.status(400).send("Report fail to update.");
                  });
              })
              .catch((e) => {
                res.status(400).send("Report fail to update.");
              });
          });
        });
      } catch (error) {
        res.status(500).send("Internal Server Error");
      }
    } else {
      res.status(404).send("Database is turned off.");
      return;
    }
  }
);

app.post("/api/fetch-published-reports", verifyToken, (req, res) => {
  const { uid } = req.body;
  const role = req.user.data.role;
  if (!uid || !role) {
    res.status(400).send("Incomplete parameters.");
    return;
  }

  if (connectToDbStat) {
    if (role === "admin") {
      db.collection("hnch-reports")
        .where("opr", "==", "publish")
        .get()
        .then((report) => {
          let obj = [];
          report.forEach((rep) => {
            let temp = rep.data();
            temp.rp_id = rep.id;
            obj.push(temp);
          });
          const sort = obj
            .slice()
            .sort((a, b) => new Date(b.rcv_when) - new Date(a.rcv_when));
          res.status(200).json(sort);
        })
        .catch((e) => {
          res.status(500).send("Database error.");
        });
    } else {
      db.collection("hnch-reports")
        .where("reporter.uid", "==", uid)
        .where("opr", "==", "publish")
        .get()
        .then((report) => {
          let obj = [];
          report.forEach((rep) => {
            let temp = rep.data();
            temp.rp_id = rep.id;
            obj.push(temp);
          });
          const sort = obj
            .slice()
            .sort(
              (a, b) => new Date(b.publish_date) - new Date(a.publish_date)
            );
          res.status(200).json(sort);
        })
        .catch((e) => {
          res.status(500).send("Database error.");
        });
    }
  } else {
    res.status(404).send("Database is turned off.");
    return;
  }
});

app.post("/api/fetch-report-information", verifyToken, (req, res) => {
  const { rp_id } = req.body;

  if (!rp_id) {
    res.status(400).send("Incomplete parameters.");
    return;
  }

  if (connectToDbStat) {
    db.collection("hnch-reports")
      .doc(rp_id)
      .get()
      .then((d) => {
        db.collection("hnch-transactions")
          .where("report_id", "==", rp_id)
          .get()
          .then((d2) => {
            if (d2.size === 0) {
              res.status(404).json("Report not found.");
              return;
            }
            let arr = [];

            d2.forEach((d3) => {
              arr.push(d3.data());
            });
            let obj = {
              ...d.data(),
              corr_tr: arr,
            };
            res.status(200).json(obj);
          })
          .catch((e2) => {
            res.status(500).send("Database error.");
            return;
          });
        return;
      })
      .catch((e) => {
        res.status(500).send("Database error.");
        return;
      });
  } else {
    res.status(404).send("Database is turned off.");
    return;
  }
});

app.put("/api/send-reim-notice", verifyToken, (req, res) => {
  const { rp_id, fn, mn, ln, notice } = req.body;
  const role = req.user.data.role;

  if (!rp_id || !fn || !mn || !ln || !notice || !role) {
    res.status(400).send("Incomplete parameters.");
    return;
  }

  if (role !== "admin") {
    res.status(401).send("Unauthorized. - Role not met.");
    return;
  }

  if (connectToDbStat) {
    db.collection("hnch-reports")
      .doc(rp_id)
      .update({
        reimbursement: {
          notice: {
            status: true,
            admin_fn: fn,
            admin_mn: mn,
            admin_ln: ln,
            description: notice,
            uploaded_on: momentTZ()
              .tz("Asia/Manila")
              .format("hh:mm A, MMM DD 'YY"),
          },
        },
      })
      .then((d) => {
        res.status(200).send("Notice uploaded.");
      })
      .catch((e) => {
        res.status(400).send("Notice fail to upload.");
      });
  } else {
    res.status(404).send("Database is turned off.");
    return;
  }
});

app.listen(process.env.PORT, () => {
  if (connectToDbStat) {
    connectToDb();
  }
  console.log(`Server is listening at PORT ${process.env.PORT}.`);
});

// rules_version = '2';

// service cloud.firestore {
//   match /databases/{database}/documents {
//     match /{document=**} {
//       allow read, write: if false;
//     }
//   }
// }
