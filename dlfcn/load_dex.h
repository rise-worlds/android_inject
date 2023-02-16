#ifndef __LOAD_DEX_H__
#define __LOAD_DEX_H__
#include <jni.h>

int ClearException(JNIEnv *jenv);

int makeDexElements(JNIEnv *env, jobject classLoader, jobject dexFileobj);

jobject getClassLoader(JNIEnv *jenv);

jclass loadCLass_plan_one(JNIEnv *jenv, const char *name, jobject dexObject);

jclass loadCLass_plan_two(JNIEnv *jenv, const char *name);

jclass findAppClass_test(JNIEnv *jenv, const char *name, jobject dexObject);

jobject LoadDex(JNIEnv *jenv, const char *dexPath, const char *pKgName);

jclass myFindClass(JNIEnv *jenv, const char *targetClassName, jobject dexObj);

jobject createNewClassLoader(JNIEnv *env, const char *jarpath, char *nativepath);

jclass findClassFromLoader(JNIEnv *env, jobject class_loader, const char *class_name);

#endif