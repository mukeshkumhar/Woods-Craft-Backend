import asyncHandler from "../utils/asyncHandler.js";
import ApiError from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import ApiResponse from "../utils/ApiResponse.js";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);

    const AccessToken = await user.GenerateAccessToken();
    const RefreshToken = await user.GenerateRefreshToken();

    user.refreshToken = RefreshToken;
    user.save();

    return { AccessToken, RefreshToken };
  } catch (error) {
    console.log(error);
    throw new ApiError(
      500,
      "Something went wrong while generating access and refresh tokens"
    );
  }
};

const RegisterUser = asyncHandler(async (req, res) => {
  /*fetch data from frontend
      check for validation
      check if user already exist
      check for file, avatar
      check for file upload process, cloudinary
      create new user obj
      remove password and refresh tokens from response
      check for user creation
      res.send( user )
      */

  const { fullName, email, age, address, passkey } = req.body;
  console.log("From Body -> " + req.body);

  if ([fullName, email, address].some((field) => !field || field.trim() === "")
  ) {
    throw new ApiError(400, "all field are required");
  }


  if (!age) throw new ApiError(401, "Please provide your age");
  if (!passkey)
    throw new ApiError(401, "Password is compulsory ! Please provide password");

  if (!email.includes("@")) throw new ApiError(400, "Please enter valid email");

  const ExistedUser = await User.findOne({ email });

  if (ExistedUser) throw new ApiError(400, "Given email is already registered");

  const user = await User.create({
    fullName,
    email,
    age,
    address,
    passkey: passkey,
    admin: false,
  });

  const CreatedUser = await User.findById(user._id).select(
    "-passkey -refreshToken -createdAt -updatedAt -cart -likedProduct -productHistory"
  );

  if (!CreatedUser)
    throw new ApiError(500, "Something went wrong while user registration");

  const { AccessToken, RefreshToken } = await generateAccessAndRefreshTokens(
    CreatedUser?._id
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  res
    .status(201)
    .cookie("RefreshToken", RefreshToken, options)
    .cookie("AccessToken", AccessToken, options)
    .json(
      new ApiResponse(
        201,
        { User: CreatedUser, RefreshToken, AccessToken },
        "User registration completed successfully"
      )
    );
});

const LogInUser = asyncHandler(async (req, res) => {
  /*
      1. get the logIn data from req.body - username, email, password
      2. check for the authentication data
      3. check if the user is available or not
      4. check for password
      5. generate refresh & access tokens
      6 give response
      */

  const { email, passkey } = req.body;

  if (!email || !passkey)
    throw new ApiError(401, "email and password are required");

  const user = await User.findOne({ email });

  if (!user) throw new ApiError(404, "Provided email is not found");

  const isValid = await user.isPasswordCorrect(passkey);

  if (!isValid) throw new ApiError(401, "Entered Credential is not correct");

  const { AccessToken, RefreshToken } = await generateAccessAndRefreshTokens(
    user?._id
  );

  const logedInUser = await User.findById(user._id).select(
    "-passkey -refreshToken -createdAt -updatedAt -cart -likedProduct -productHistory"
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(201)
    .cookie("RefreshToken", RefreshToken, options)
    .cookie("AccessToken", AccessToken, options)
    .json(
      new ApiResponse(
        201,
        {
          User: logedInUser,
          RefreshToken,
          AccessToken,
        },
        "User Loged In successfully"
      )
    );
});

const LogOutUser = asyncHandler(async (req, res) => {

  const LogedOutUser = await User.findOneAndUpdate(req.user._id, {
    $set: {
      refreshToken: "1",
    },
  });

  LogedOutUser.save()

  console.log(LogedOutUser)
  console.log("reached Logout");

  const options = {
    httpOnly: true,
    secure: true,
  };



  return res
    .status(200)
    .clearCookie("AccessToken", options)
    .clearCookie("RefreshToken", options);
});

const regenerateRefreshToken = asyncHandler(async (req, res) => {
  try {
    const token = req.cookies.RefreshToken || req.body.RefreshToken;

    if (!token) throw new ApiError(401, "Unauthorized request");

    const DecodedToken = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);

    const user = await User.findById(DecodedToken._id).select(
      "-password -refreshToken"
    );

    if (!user) throw new ApiError(400, "Invalid Token");

    const { RefreshToken, AccessToken } = await generateAccessAndRefreshTokens(
      user._id
    );

    const options = {
      httpOnly: true,
      secure: true,
    };

    return res
      .status(201)
      .cookie("RefreshToken", RefreshToken, options)
      .cookie("AccessToken", AccessToken, options)
      .json(
        new ApiResponse(
          201,
          {
            RefreshToken,
            AccessToken,
          },
          "Refresh token regenerated successfully"
        )
      );
  } catch (error) {
    throw new ApiError(401, error.message || "Invalid Token");
  }
});

const ChangeCurrentPassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  const user = await User.findById(req.user?._id);

  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

  if (!isPasswordCorrect) {
    throw new ApiError(400, "Invalid password");
  }

  user.password = newPassword;

  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully"));
});

const GetUser = asyncHandler(async (req, res) => {
  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { user: req.user },
        "Get request successfully executed"
      )
    );
});

const UpdateUserDetails = asyncHandler(async (req, res) => {
  const { fullName, email } = req.body;

  if (!fullName || !email) {
    throw new ApiError(400, "all fields are required");
  }

  const user = await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        fullName,
        email,
      },
    },
    { new: true }
  ).select("-password");

  return res
    .status(200)
    .json(new ApiResponse(200, { user }, "User updation successfully"));
});

const GetOrderHistory = asyncHandler(async (req, res) => {
  const user = await User.aggregate([
    {
      $match: {
        _id: new mongoose.Types.ObjectId(req.user._id),
      },
    },
    {
      $lookup: {
        from: "videos",
        localField: "watchHistory",
        foreignField: "_id",
        as: "WatchHistoryLookUp",
        pipeline: [
          {
            $lookup: {
              from: "users",
              localField: "owner",
              foreignField: "_id",
              as: "owner",
              pipeline: [
                {
                  $project: {
                    fullName: 1,
                    username: 1,
                    avatar: 1,
                  },
                },
              ],
            },
          },
          {
            $addFields: {
              owner: {
                $arrayElemAt: ["$owner", 0],
              },
            },
          },
        ],
      },
    },
  ]);

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        user[0].watchHistory,
        "Watch history fetched successfully"
      )
    );
});

export {
  GetUser,
  LogInUser,
  LogOutUser,
  RegisterUser,
  GetOrderHistory,
  UpdateUserDetails,
  ChangeCurrentPassword,
  regenerateRefreshToken,
};
