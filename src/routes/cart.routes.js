import { Router } from "express";
import {
  GetCart,
  AddToCart,
  GetWishlist,
  AddToWishlist,
  DeleteFromCart,
  DeleteFromWishlist,
} from "../controllers/cart.controller.js";
import { VerifyUser } from "../middlewares/auth.middleware.js";

const router = Router();

router.use(VerifyUser); // Apply VerifyUser middleware to all routes in this file

// Routes for cart
router.route("/cart/")
  .get(GetCart);

router.route("/cart/:productId")
  .post(AddToCart)
  .delete(DeleteFromCart);

// Routes for wishlists
router.route("/wishlist/")
  .get(GetWishlist);

router.route("/wishlist/:productId")
  .post(VerifyUser, AddToWishlist)
  .delete(VerifyUser ,DeleteFromWishlist);

export default router;
