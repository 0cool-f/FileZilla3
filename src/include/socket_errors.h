#ifndef FILEZILLA_ENGINE_SOCKET_ERRORS_HEADER
#define FILEZILLA_ENGINE_SOCKET_ERRORS_HEADER

namespace fz {

/**
 * \brief Gets a symbolic name for socket errors.
 *
 * \example error_string(EAGAIN) == "EAGAIN"
 *
 * \return name if the error code is known
 * \return number as string if the error code is not known
 */
std::string socket_error_string(int error);

/**
 * \brief Gets a human-readable, translated description of the error
 */
native_string socket_error_description(int error);

}

#endif
