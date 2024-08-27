package ra.security_demo.advice;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import ra.security_demo.exception.CustomException;

@RestControllerAdvice
public class ApplicationHandler
{
    @ExceptionHandler(CustomException.class)
    public ResponseEntity<?> handleCustomException(CustomException e)
    {
        return new ResponseEntity<>(e.getMessage(), e.getStatus());
    }


}