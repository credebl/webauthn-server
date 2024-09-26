// src/logger.ts
import { createLogger, format, transports } from 'winston';
const { combine, timestamp, printf, colorize } = format;

// Custom log format
const customFormat = printf(({ level, message, timestamp }) => {
  return `${timestamp} ${level}: ${message}`;
});

// Create Winston logger instance
const logger = createLogger({
  level: 'info', 
  format: combine(
    timestamp(),    
    colorize(),     
    customFormat  
  ),
  transports: [
    new transports.Console(),  // Log to the console
    new transports.File({ filename: 'combined.log' })  // Log to a file
  ],
});

export default logger;