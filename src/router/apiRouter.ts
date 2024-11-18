import { Router } from 'express'
import apiController from '../controller/apiController'
import rateLimit from '../middleware/rateLimit'
import userController from '../controller/userController'

const router = Router()

router.use(rateLimit)
router.route('/self').get(apiController.self)
router.route('/health').get(apiController.health)

//User router
router.route('/register').post(userController.register)

export default router
