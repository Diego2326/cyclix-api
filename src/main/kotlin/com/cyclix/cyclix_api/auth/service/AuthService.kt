package com.cyclix.cyclix_api.auth.service

import com.cyclix.cyclix_api.auth.dto.RegisterRequest
import com.cyclix.cyclix_api.user.RoleRepository
import com.cyclix.cyclix_api.user.User
import com.cyclix.cyclix_api.user.UserRepository
import com.cyclix.cyclix_api.user.UserStatusRepository
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class AuthService(
    private val userRepository: UserRepository,
    private val roleRepository: RoleRepository,
    private val userStatusRepository: UserStatusRepository,
    private val passwordEncoder: PasswordEncoder
) {
    @Transactional
    fun register(request: RegisterRequest): Long {
        val normalizedEmail = request.email.trim().lowercase()
        val rawPassword = request.password ?: throw IllegalArgumentException("La contraseña es obligatoria")

        if (userRepository.existsByEmail(normalizedEmail)) {
            throw IllegalArgumentException("El correo ya está registrado")
        }

        val userRole = roleRepository.findByName("USER")
            .orElseThrow { IllegalStateException("No existe el rol USER") }

        val activeStatus = userStatusRepository.findByName("ACTIVE")
            .orElseThrow { IllegalStateException("No existe el estado ACTIVE") }

        val user = User(
            firstName = request.firstName.trim(),
            lastName = request.lastName?.trim()?.takeIf { it.isNotBlank() },
            email = normalizedEmail,
            phone = request.phone?.trim()?.takeIf { it.isNotBlank() },
            passwordHash = requireNotNull(passwordEncoder.encode(rawPassword)),
            role = userRole,
            status = activeStatus
        )

        return userRepository.save(user).id
    }
}
