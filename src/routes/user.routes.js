import { Router } from "express";
import {
    GetUser,
    LogInUser,
    LogOutUser,
    RegisterUser,
    GetOrderHistory,
    UpdateUserDetails,
    ChangeCurrentPassword,
    regenerateRefreshToken,
} from "../controllers/User.controller.js";
import { VerifyUser } from "../middlewares/auth.middleware.js";

// Initializing router
const router = Router();

// Register route
router.route("/register").post(RegisterUser);
router.route("/login").post(LogInUser);

// secure routes

router.route("/logout").post(VerifyUser, LogOutUser);
router.route("/refresh-token").get(VerifyUser, regenerateRefreshToken);
router.route("/change-password").post(VerifyUser, ChangeCurrentPassword);
router.route("/get-user").get(VerifyUser, GetUser);
router.route("/update-user-details").patch(VerifyUser, UpdateUserDetails);
router.route("/get-watch-history").get(VerifyUser, GetOrderHistory);

export default router;
