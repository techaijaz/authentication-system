import { Router } from 'express'
import apiController from '../controller/apiController'
import rateLimit from '../middleware/rateLimit'
import userController from '../controller/userController'
import authentication from '../middleware/authentication'

const router = Router()

router.use(rateLimit)
router.route('/self').get(apiController.self)
router.route('/health').get(apiController.health)

//User router
router.route('/register').post(userController.register)
router.route('/confirmation/:token').put(userController.confirmation)
router.route('/login').get(userController.login)
router.route('/self-identification').get(authentication, userController.selfIdentification)
router.route('/logout').put(authentication, userController.logout)
router.route('/refresh-token').post(userController.refresshToken)
router.route('/forgot-password').put(userController.forgotPassword)
router.route('/reset-password/:token').put(userController.resetPassword)
router.route('/change-password').put(authentication, userController.changePassword)

export default router
