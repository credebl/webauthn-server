FROM node:16-alpine
#RUN kill -9 sudo lsof -t -i:8000
WORKDIR /app
COPY package.json ./
RUN rm -rf node_moduls
RUN npm i
COPY . .
RUN npm cache clean --force
CMD [ "npm", "start" ]

# docker build -t webauthn .
# docker tag docker.io/library/webauthn docker tag docker.io/library/webauthn 668004263903.dkr.ecr.ap-south-1.amazonaws.com/credebl2.0:webauthn