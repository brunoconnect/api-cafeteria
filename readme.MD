Api Cafeteria

Comandos utilizados no projeto

NODE
	
	Start projeto
	- yarn dev 

Criar um projeto em node
	- yarn init - y
	- yarn add typescript -D
	- yarn add express
	- yarn add @types/express -D
	- yarn tsc --init
	- yarn add ts-node-dev -D
	- yarn add nodemon -D
	
	no package.json criar em baixo de license
	"license": "MIT",
	"scripts": {
    "dev": "ts-node-dev --transpile-only src/server.ts"
  },
  
  TRATAR ERROS
	- yarn add express-async-errors
	
	CORS
	- yarn add cors
	- yarn add @types/cors -D
	
	BANCO DE DADOS
	- yarn add prisma
	- yarn add @prisma/client
	- npx prisma init
	
	CRIAR TABELAS NO BANCO DEPOIS DE TER COLOCADO ELAS NO PRISMA
	- yarn prisma migrate dev
	
	BCRYPT
	- yarn add bcryptjs
	- yarn add @types/bcryptjs -D
	
	TOKEN
	- yarn add jsonwebtoken
	- yarn add @types/jsonwebtoken -D
	
	NO TS CONFIG DESABILITAR O STRICT
	"strict": true, SÓ PRECISA COLOCAR PRA FALSE 
	
	"typeRoots": [
      "./src/@types"
    ],  