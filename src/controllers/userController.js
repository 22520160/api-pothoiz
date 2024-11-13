const { createResetToken, createUserService, loginService, getUserService, sendResetEmail, findUserByEmail, updateUserPassword } = require("../services/userService");
const jwt = require('jsonwebtoken');

const createUser = async (req, res) => {
    const { name, email, password } = req.body;
     // Kiểm tra độ phức tạp của mật khẩu
     const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\W).{6,}$/;
     if (!passwordRegex.test(password)) {
         return res.status(400).json({
             message: 'Mật khẩu phải có ít nhất 6 ký tự, bao gồm chữ cái in hoa, chữ cái thường, và ký tự đặc biệt.'
         });
     }
    const data = await createUserService(name, email, password);
    return res.status(200).json(data);
};

const handleLogin = async (req, res) => {
    const { email, password } = req.body;
    const data = await loginService(email, password);
    return res.status(200).json(data);
};

const getUser = async (req, res) => {
    const data = await getUserService();
    return res.status(200).json(data);
};

// Controller cho quên mật khẩu
const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ message: "Email is required" });
        }
        
        const user = await findUserByEmail(email);
        if (!user) return res.status(404).json({ message: 'User does not exist' });

        const token = createResetToken(user.id);
        await sendResetEmail(email, token);

        res.status(200).json({ message: 'Password reset email sent' });
    } catch (error) {
        console.error("Forgot password error:", error);
        res.status(500).json({ message: "An error occurred" });
    }
};

// Controller cho đặt lại mật khẩu
const resetPassword = async (req, res) => {
    const { token, newPassword } = req.body;
// Kiểm tra độ phức tạp của mật khẩu mới
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\W).{6,}$/;
if (!passwordRegex.test(newPassword)) {
    return res.status(400).json({
        message: 'Mật khẩu phải có ít nhất 6 ký tự, bao gồm chữ cái in hoa, chữ cái thường, và ký tự đặc biệt.'
    });
}

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.userId;

        // Cập nhật mật khẩu mà không mã hóa
        const success = await updateUserPassword(userId, newPassword);
        if (success) {
            res.status(200).json({ message: 'Mật khẩu đã được cập nhật thành công' });
        } else {
            res.status(400).json({ message: 'Không thể cập nhật mật khẩu' });
        }
    } catch (error) {
        console.log("Error in resetPassword:", error);
        res.status(400).json({ message: 'Đã có lỗi, cập nhật mật khẩu thất bại!' });
    }
};

module.exports = {
    createUser,
    handleLogin,
    getUser,
    forgotPassword,
    resetPassword
};
