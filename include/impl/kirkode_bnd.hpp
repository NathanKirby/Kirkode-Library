#pragma once
#ifndef KIR_EXCLUDE_BND
/**
 * \brief Executes an expression and catches any exception.
 *
 * \param unsafe: Expression to execute.
 *
 * \return true if the expression succeeds, false if an exception is thrown.
 */
#define K_NOEXCEPT(unsafe) \
/**/([&]() noexcept -> bool { \
/**//**/try { \
/**//**//**/(unsafe); \
/**//**//**/return true; \
/**//**/} catch (...) { \
/**//**//**/return false; \
/**//**/} \
/**/}())

 /**
  * \brief Executes a function call and catches any exception.
  *
  * \param unsafe: Function call to execute.
  *
  * \return true if the function succeeds, false if an exception is thrown.
  */
#define K_NOEXCEPT_B(unsafe) \
/**/([&]() noexcept -> bool { \
/**//**/try { \
/**//**//**/(unsafe); \
/**//**//**/return true; \
/**//**/} catch (...) { \
/**//**//**/return false; \
/**//**/} \
/**/}())

  /**
   * \brief Executes an expression and handles any exception with a specified action.
   *
   * \param unsafe: Expression to execute.
   * \param ecase: Expression to execute if an exception is thrown.
   */
#define K_NOEXCEPT_H(unsafe, ecase) \
/**/([&]() noexcept -> void { \
/**//**/try { \
/**//**//**/(unsafe); \
/**//**/} catch (...) { \
/**//**//**/(ecase); \
/**//**/} \
/**/}())
#endif // KIR_EXCLUDE_BND