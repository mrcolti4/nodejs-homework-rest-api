import express from "express";
import authController from "../../controllers/auth-controller.js";
import { validateBody } from "../../decorators/index.js";

import {
  userSignupSchema,
  userSigninSchema,
  userEmailSchema,
} from "../../models/User.js";
import { authenticate, upload, isEmptyBody } from "../../middlewares/index.js";

const userSignupValidate = validateBody(userSignupSchema);
const userSigninValidate = validateBody(userSigninSchema);
const userEmailValidate = validateBody(userEmailSchema);

const authRouter = express.Router();

authRouter.post(
  "/register",
  isEmptyBody,
  userSignupValidate,
  authController.register
);
authRouter.post(
  "/login",
  isEmptyBody,
  userSigninValidate,
  authController.login
);
authRouter.post(
  "/verify",
  isEmptyBody,
  userEmailValidate,
  authController.resendVerifyEmail
);
authRouter.post("/logout", authenticate, authController.logout);

authRouter.get("/current", authenticate, authController.getCurrent);
authRouter.get("/verify/:verificationToken", authController.verify);

authRouter.patch(
  "/avatars",
  upload.single("avatarURL"),
  authenticate,
  authController.changeAvatar
);

export default authRouter;
