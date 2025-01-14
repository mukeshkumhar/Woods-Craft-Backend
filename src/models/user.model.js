import mongoose, { Schema } from "mongoose";
import Jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const userSchema = new Schema(
    {
        fullName: {
            type: String,
            required: true,
            trim: true,
        },
        email: {
            type: String,
            required: true,
            unique: true,
            trim: true,
        },
        age: {
            type: Number,
            required: true,
            trim: true,
        },
        address: {
            type: String,
            required: true,
            trim: true,
        },
        cart: [
            {
                type: Schema.Types.ObjectId,
                ref: "Product",
            },
        ],
        likedProduct: [
            {
                type: Schema.Types.ObjectId,
                ref: "Product",
            },
        ],
        productHistory: [
            {
                type: Schema.Types.ObjectId,
                ref: "Product",
            },
        ],
        passkey: {
            type: String,
            required: [true, "Password is required"],
        },
        admin: {
            type: Boolean,
            default: false,
        },
        refreshToken: {
            type: String,
        },
    },
    { timestamps: true }
);

userSchema.pre("save", async function (next) {
    if (!this.isModified("passkey")) return next();

    this.passkey = await bcrypt.hash(this.passkey, 10);
    next();
});

userSchema.methods.isPasswordCorrect = async function (passkey) {
    return await bcrypt.compare(passkey, this.passkey);
};

userSchema.methods.GenerateAccessToken = function () {
    return Jwt.sign(
        {
            _id: this._id,
            email: this.email,
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
        }
    );
};

userSchema.methods.GenerateRefreshToken = function () {
    return Jwt.sign(
        {
            _id: this._id,
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
        }
    );
};

export const User = mongoose.model("User", userSchema);
