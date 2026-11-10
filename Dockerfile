FROM node:22-alpine
WORKDIR /app
COPY package.json server.js app.js styles.css noir-store.html ./
ENV NODE_ENV=production HOST=0.0.0.0 PORT=3000 DB_PATH=/app/data/noir.sqlite UPLOAD_DIR=/app/uploads
RUN mkdir -p /app/data /app/uploads && chown -R node:node /app
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s CMD node -e "fetch('http://127.0.0.1:3000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["npm", "start"]
