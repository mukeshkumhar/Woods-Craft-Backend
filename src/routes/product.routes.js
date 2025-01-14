import { Router } from "express";
import {
  AddImages,
  DeleteProduct,
  GetAllProducts,
  UploadNewProduct,
  GetProductDetails,
  UpdateProductDetails,
  ClearAndUpdateImages,
} from "../controllers/product.controller.js";
import { upload } from "../middlewares/multer.middleware.js";
import { VerifyAdmin } from "../middlewares/checkAdmin.middleware.js";

const router = Router();
// router.use(VerifyUser); // Apply VerifyUser middleware to all routes in this file

router
  .route("/new-product")
  .post(VerifyAdmin, upload.single("images"), UploadNewProduct)
  .get(GetAllProducts);

router
  .route("/img-update/:productId")
  .patch(VerifyAdmin, upload.array("Images", 4), AddImages);

router
  .route("/update-all-images/:productId")
  .patch(VerifyAdmin, upload.array("Images"), ClearAndUpdateImages);

router
  .route("/update-product-details/:productId")
  .get(GetProductDetails)
  .patch(VerifyAdmin, UpdateProductDetails)
  .delete(VerifyAdmin, DeleteProduct);

export default router;
