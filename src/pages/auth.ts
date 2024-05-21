import { Account } from 'next-auth';
import { NextAuthOptions, User} from 'next-auth';
import { AdapterUser } from 'next-auth/adapters';
import { JWT } from 'next-auth/jwt';
import AzureADProvider from 'next-auth/providers/azure-ad';

const env = process.env;


export async function refreshAccessToken(token: JWT) { 
  try {
    const url = `https://login.microsoftonline.com/${env.NEXT_PUBLIC_AZURE_AD_TENANT_ID}/oauth2/v2.0/token`;

    const body = new URLSearchParams({
      client_id:
        process.env.NEXT_PUBLIC_AZURE_AD_CLIENT_ID || 'azure-ad-client-id',
      client_secret:
        process.env.NEXT_PUBLIC_AZURE_AD_CLIENT_SECRET ||
        'azure-ad-client-secret',
      scope: 'email openid profile User.Read offline_access',
      grant_type: 'refresh_token',
      refresh_token: token.refreshToken as string,
    });

    const response = await fetch(url, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      method: 'POST',
      body,
    });

    const refreshedTokens = await response.json();

    if (!response.ok) {
      throw refreshedTokens;
    }

    return {
      ...token,
      accessToken: refreshedTokens.id_token as string,
      accessTokenExpires: Date.now() + refreshedTokens.expires_in * 1000 as number,
      refreshToken: refreshedTokens.refresh_token as string,
    };
  } catch (error) {
    return {
      ...token,
      error: 'RefreshAccessTokenError',
    };
  }
}


export const authOptions: NextAuthOptions = {
  providers: [
    AzureADProvider({
      clientId: `${env.NEXT_PUBLIC_AZURE_AD_CLIENT_ID}`,
      clientSecret: `${env.NEXT_PUBLIC_AZURE_AD_CLIENT_SECRET}`,
      tenantId: `${env.NEXT_PUBLIC_AZURE_AD_TENANT_ID}`,
      authorization: {
        params: { scope: 'openid email profile User.Read  offline_access' },
      },
      httpOptions: { timeout: 10000 },
    }),
  ],
  callbacks: {
   jwt: async ({ user, token, account }:{user?: User| AdapterUser | undefined, token:JWT, account:  Account | null})=>{
    
    if(account && user){
      //Initial login check
     return {
      accessToken: account.id_token,
      accessTokenExpires: account?.expires_at
        ? account.expires_at * 1000
        : 0,
      refreshToken: account.refresh_token,
      user,
     }
     }if(Date.now() > token.accessTokenExpires ){
      // Refresh token when expire (every 1hrs)
      return refreshAccessToken(token);
   } else {
      return token;
   } 
     },
   session: async({ session, token }) =>{
    return {
      ...session,
      ...token
    }
   }
  },
};
