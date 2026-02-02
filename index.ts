import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import path from "path";
import fs from "fs";
import jwt from "jsonwebtoken";

const app = express();
const PORT = 3000;
const JWT_SECRET = "SuperSecretDoNotShareToAnyoneElse";

app.set("trust proxy", 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// --- Rate Limiter ---
app.use(
  rateLimit({
    windowMs: 60_000,
    max: 50,
    standardHeaders: true,
    legacyHeaders: false,
  }),
);

// --- Logging ---
app.use((req: Request, _res: Response, next: NextFunction) => {
  console.log(`[REQ] ${req.method} ${req.path}`);
  next();
});

/**
 * @note validate login - Signs the initial JWT
 */
app.all(
  "/player/growid/login/validate",
  async (req: Request, res: Response) => {
    try {
      const formData = req.body as Record<string, string>;
      const growId = formData.growId;
      const password = formData.password;

      if (!growId || !password) {
        return res
          .status(400)
          .json({ status: "error", message: "Missing credentials" });
      }

      // Create a secure JWT payload
      const token = jwt.sign(
        { growid: growId, password: password },
        JWT_SECRET,
        { expiresIn: "24h" },
      );

      res.json({
        status: "success",
        message: "Account Validated.",
        token,
        url: "",
        accountType: "growtopia",
      });
    } catch (error: any) {
      res
        .status(500)
        .json({ status: "error", message: "Internal Server Error" });
    }
  },
);

/**
 * @note checktoken - Verifies the JWT instead of manual string replacement
 */
app.all(
  "/player/growid/validate/checktoken",
  async (req: Request, res: Response) => {
    try {
      const body = req.body;
      const refreshToken = body.data?.refreshToken || body.refreshToken;
      const clientData = body.data?.clientData || body.clientData;

      if (!refreshToken) {
        return res
          .status(400)
          .json({ status: "error", message: "Missing token" });
      }

      // 1. Verify the JWT. If it's tampered with or expired, it throws an error.
      const decoded = jwt.verify(refreshToken, JWT_SECRET) as any;

      // 2. Optional: If you need to embed clientData into a new token
      // (This replaces your manual Buffer.replace logic)
      const newToken = jwt.sign(
        {
          ...decoded,
          clientData: Buffer.from(clientData || "").toString("base64"),
        },
        JWT_SECRET,
      );

      res.json({
        status: "success",
        message: "Token is valid.",
        token: newToken,
        url: "",
        accountType: "growtopia",
      });
    } catch (error: any) {
      console.log(`[JWT ERROR]: ${error.message}`);
      res.status(401).json({
        status: "error",
        message: "Invalid or expired token",
      });
    }
  },
);

app.all("/player/growid/checktoken", (req, res) =>
  res.redirect(307, "/player/growid/validate/checktoken"),
);

// ... rest of your static file and dashboard logic ...

app.listen(PORT, () =>
  console.log(`[SERVER] Running on http://localhost:${PORT}`),
);

export default app;
