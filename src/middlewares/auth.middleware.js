import { User } from "../models/user.model.js";
import ApiError from "../utils/ApiError.js";
import asyncHandler from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken";

export const VerifyUser = asyncHandler(async (req, res, next) => {
    try {
        // console.log(req.cookies);
        const token =
            req.cookies.AccessToken ||
            req.header("Authorization")?.replace("Bearer ", "");

        if (!token) throw new ApiError(401, "Unauthorized request");

        const DecodedToken = jwt.verify(
            token,
            process.env.ACCESS_TOKEN_SECRET
        );

        const user = await User.findById(DecodedToken._id).select(
            "-password -refreshToken"
        );

        if (!user) throw new ApiError(400, "Invalid Token");

        req.user = user;
        next();
    } catch (error) {
        throw new ApiError(401, error.message || "Invalid Token");
    }
});
